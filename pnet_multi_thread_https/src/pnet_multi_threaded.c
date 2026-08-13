/*
 * pnet_multi_threaded.c
 *
 * Autonomous multi-threaded customer flow application.
 * Completely independent from pnet.c — compiled instead of it.
 *
 * To switch to this file, update CMakeLists.txt:
 *   target_sources(app PRIVATE src/pnet_multi_threaded.c)
 *
 * Thread architecture:
 * +----------------------------------------------------------------------+
 * | mt_flow_thread  (prio 6)  WiFi+MQTT connect/reconnect state machine  |
 * | mt_mqtt_poll    (prio 7)  MQTT keepalive / poll / ping               |
 * | mt_publish      (prio 8)  Publish + DNS resolve every 60s            |
 * | mt_udp          (prio 9)  Parallel UDP socket TX/RX every 30s        |
 * +----------------------------------------------------------------------+
 *
 * Socket fd map during steady state:
 *   fd=0  DNS UDP socket   (created by DNS resolver at DHCP time)
 *   fd=1  MQTT TCP/TLS     (created at MQTT connect)
 *   fd=2  UDP test socket  (created by mt_udp thread)
 *
 * To test UDP echo responses, run on your PC:
 *   python3 -c "
 *   import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
 *   s.bind(('',5005)); print('UDP echo on :5005')
 *   while True:
 *       d,a=s.recvfrom(256); print('RX:',d); s.sendto(d,a)"
 */

#include <zephyr/kernel.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/mqtt.h>
#include <string.h>
#include <stdio.h>

#if defined(CONFIG_MQTT_LIB_TLS)
#include <zephyr/net/tls_credentials.h>
#include "ca_cert.h"
#endif

#include "https_get.h"

/* ========================================================================
 * Configuration -- edit to match your environment
 * ======================================================================== */
#define MT_WIFI_SSID            "RenesasMatter"
#define MT_WIFI_PSK             "Matter2023"

#define MT_MQTT_HOST            "192.168.50.243"
#define MT_MQTT_PORT            8883U
#define MT_MQTT_CLIENT_ID       "pnet-mt-client"
#define MT_MQTT_KEEPALIVE_S     45
#define MT_MQTT_PING_INTERVAL_S 30

#define MT_SUB_TOPIC            "ra6w1_sub"
#define MT_PUB_TOPIC            "ra6w1_pub"
#define MT_PUBLISH_INTERVAL_S   60
#define MT_ENABLE_PERIODIC_DNS_DIAG 1

#define MT_UDP_TARGET_IP        "192.168.50.243"
#define MT_UDP_TARGET_PORT      5005
#define MT_UDP_LOCAL_PORT       5006
#define MT_UDP_INTERVAL_S       30
#define MT_UDP_RECV_TIMEOUT_S   5
#define MT_HOST_DIAG_INTERVAL_MS 120000

#if defined(CONFIG_MQTT_LIB_TLS)
#define MT_TLS_SEC_TAG          42
#endif

/* ========================================================================
 * Shared state
 * ======================================================================== */
static bool             mt_wifi_connected  = false;
static bool             mt_mqtt_connected  = false;
static bool             mt_mqtt_subscribed = false;
static int8_t           mt_wifi_rssi       = 0;
static bool             mt_in_ps           = false;
/* Gate UDP until HTTPS provision finishes (avoids socket/RAM races). */
static bool             mt_https_phase_done = false;
/* Filled by Phase 4 HTTPS JSON; falls back to MT_MQTT_* / ca_cert.h if invalid. */
static struct https_mqtt_cfg mt_https_mqtt_cfg;

static struct net_if   *mt_iface           = NULL;
static K_EVENT_DEFINE(mt_dhcp_event);

/* ========================================================================
 * MQTT client state
 * ======================================================================== */
static struct mqtt_client       mt_mqtt_client;
static struct sockaddr_storage  mt_mqtt_broker;
static uint8_t                  mt_mqtt_rx_buf[1024];
static uint8_t                  mt_mqtt_tx_buf[1024];
static bool                     mt_mqtt_connack_rx  = false;
static bool                     mt_mqtt_suback_rx   = false;
static bool                     mt_mqtt_puback_rx   = false;
static uint16_t                 mt_mqtt_msg_id      = 1U;
static bool                     mt_mqtt_poll_run    = false;
static struct k_work_delayable   mt_ping_dwork;

/* ========================================================================
 * Thread stacks
 * ======================================================================== */
#define MT_FLOW_STACK    8192
#define MT_POLL_STACK    4096
#define MT_PUB_STACK     4096
#define MT_UDP_STACK     8192

K_THREAD_STACK_DEFINE(mt_flow_stack,  MT_FLOW_STACK);
K_THREAD_STACK_DEFINE(mt_poll_stack,  MT_POLL_STACK);
K_THREAD_STACK_DEFINE(mt_pub_stack,   MT_PUB_STACK);
K_THREAD_STACK_DEFINE(mt_udp_stk,     MT_UDP_STACK);

static struct k_thread mt_flow_data;
static struct k_thread mt_poll_data;
static struct k_thread mt_pub_data;
static struct k_thread mt_udp_data;

static k_tid_t mt_flow_tid;
static k_tid_t mt_poll_tid;
static k_tid_t mt_pub_tid;
static k_tid_t mt_udp_tid;

/* ========================================================================
 * Event callbacks (WiFi + IPv4)
 * ======================================================================== */
static struct net_mgmt_event_callback mt_wifi_cb;
static struct net_mgmt_event_callback mt_ipv4_cb;

static void mt_ipv4_handler(struct net_mgmt_event_callback *cb,
                             uint64_t event, struct net_if *iface)
{
if (event == NET_EVENT_IPV4_DHCP_BOUND) {
char ip[NET_IPV4_ADDR_LEN];
struct net_if_ipv4 *v4 = iface->config.ip.ipv4;

if (v4 != NULL) {
for (int i = 0; i < NET_IF_MAX_IPV4_ADDR; i++) {
if (v4->unicast[i].ipv4.is_used) {
net_addr_ntop(AF_INET,
              &v4->unicast[i].ipv4.address.in_addr,
              ip, sizeof(ip));
printk("[MT] DHCP Bound: %s\n", ip);
k_event_post(&mt_dhcp_event, 1U);
break;
}
}
}
}
}

static void mt_wifi_handler(struct net_mgmt_event_callback *cb,
                             uint64_t event, struct net_if *iface)
{
const struct wifi_status *st = (const struct wifi_status *)cb->info;
ARG_UNUSED(iface);

if (event == NET_EVENT_WIFI_CONNECT_RESULT) {
if (st != NULL && st->status == 0) {
mt_wifi_connected = true;
printk("[MT] WiFi connected\n");
} else {
mt_wifi_connected = false;
printk("[MT] WiFi connect failed (status=%d)\n",
       st ? st->status : -1);
}
} else if (event == NET_EVENT_WIFI_DISCONNECT_RESULT) {
mt_wifi_connected  = false;
mt_mqtt_connected  = false;
mt_mqtt_subscribed = false;
printk("[MT] WiFi disconnected\n");
}
}

/* ========================================================================
 * Power Save helpers
 * ======================================================================== */
static int mt_ps_enable(bool on)
{
struct wifi_ps_params p = { 0 };

p.type    = WIFI_PS_PARAM_STATE;
p.enabled = on ? WIFI_PS_ENABLED : WIFI_PS_DISABLED;
if (net_mgmt(NET_REQUEST_WIFI_PS, mt_iface, &p, sizeof(p))) {
return -EIO;
}
mt_in_ps = on;
printk("[MT] PS %s\n", on ? "enabled" : "disabled");
return 0;
}

static void mt_log_host_diag(void)
{
struct net_if *iface = (mt_iface != NULL) ? mt_iface : net_if_get_default();
struct wifi_iface_status iface_status = { 0 };
int rc = -ENODEV;

if (iface != NULL) {
rc = net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, iface,
              &iface_status, sizeof(iface_status));
}

if (rc == 0) {
mt_wifi_rssi = iface_status.rssi;
printk("[HOST DIAG] RSSI=%d dBm, wifi_connected=%d, mqtt_connected=%d, ps=%d\n",
       mt_wifi_rssi,
       mt_wifi_connected ? 1 : 0,
       mt_mqtt_connected ? 1 : 0,
       mt_in_ps ? 1 : 0);
} else {
printk("[HOST DIAG] RSSI fetch failed: rc=%d, wifi_connected=%d, mqtt_connected=%d, ps=%d\n",
       rc,
       mt_wifi_connected ? 1 : 0,
       mt_mqtt_connected ? 1 : 0,
       mt_in_ps ? 1 : 0);
}
}

/* ========================================================================
 * MQTT helpers
 * ======================================================================== */
static uint16_t mt_next_msg_id(void)
{
if (++mt_mqtt_msg_id == 0U) {
mt_mqtt_msg_id = 1U;
}
return mt_mqtt_msg_id;
}

static int mt_mqtt_poll_once(int timeout_ms)
{
int sock = -1;
struct zsock_pollfd pfd;
int rc;

#if defined(CONFIG_MQTT_LIB_TLS)
if (mt_mqtt_client.transport.type == MQTT_TRANSPORT_SECURE) {
sock = mt_mqtt_client.transport.tls.sock;
} else
#endif
if (mt_mqtt_client.transport.type == MQTT_TRANSPORT_NON_SECURE) {
sock = mt_mqtt_client.transport.tcp.sock;
}

if (sock < 0) {
return -ENOTCONN;
}

pfd.fd      = sock;
pfd.events  = ZSOCK_POLLIN;
pfd.revents = 0;

rc = zsock_poll(&pfd, 1, timeout_ms);
if (rc < 0) {
return -errno;
}

if (rc > 0 && (pfd.revents & ZSOCK_POLLIN)) {
rc = mqtt_input(&mt_mqtt_client);
if (rc != 0 && rc != -EAGAIN) {
return rc;
}
}

if (mt_mqtt_connected) {
rc = mqtt_live(&mt_mqtt_client);
if (rc != 0 && rc != -EAGAIN) {
return rc;
}
}

return 0;
}

static int mt_mqtt_wait_flag(bool *flag, int timeout_ms)
{
int64_t deadline = k_uptime_get() + timeout_ms;

while (!(*flag) && k_uptime_get() < deadline) {
int rc = mt_mqtt_poll_once(200);
if (rc < 0 && rc != -EAGAIN && rc != -ETIMEDOUT) {
return rc;
}
}
return *flag ? 0 : -ETIMEDOUT;
}

static void mt_mqtt_evt_handler(struct mqtt_client *c,
                                const struct mqtt_evt *evt)
{
ARG_UNUSED(c);

switch (evt->type) {
case MQTT_EVT_CONNACK:
printk("[MT-MQTT] CONNACK result=%d\n", evt->result);
mt_mqtt_connack_rx = true;
if (evt->result == 0) {
mt_mqtt_connected = true;
k_work_reschedule(&mt_ping_dwork,
                  K_SECONDS(MT_MQTT_PING_INTERVAL_S));
}
break;

case MQTT_EVT_DISCONNECT:
mt_mqtt_connected  = false;
mt_mqtt_connack_rx = false;
mt_mqtt_suback_rx  = false;
mt_mqtt_puback_rx  = false;
k_work_cancel_delayable(&mt_ping_dwork);
printk("[MT-MQTT] Disconnected\n");
break;

case MQTT_EVT_SUBACK:
mt_mqtt_suback_rx = true;
break;

case MQTT_EVT_PUBACK:
mt_mqtt_puback_rx = true;
break;

case MQTT_EVT_PUBLISH: {
const struct mqtt_publish_param *pub = &evt->param.publish;
uint8_t buf[64];
size_t left = pub->message.payload.len;

printk("[MT-MQTT] PUBLISH on '%.*s' (%zu bytes):\n",
       pub->message.topic.topic.size,
       pub->message.topic.topic.utf8, left);

while (left > 0) {
int n = mqtt_read_publish_payload_blocking(
c, buf, MIN(left, sizeof(buf) - 1));
if (n <= 0) {
break;
}
buf[n] = '\0';
printk("%s", buf);
left -= (size_t)n;
}
printk("\n");

if (pub->message.topic.qos == MQTT_QOS_1_AT_LEAST_ONCE) {
mqtt_publish_qos1_ack(c,
&(struct mqtt_puback_param){
.message_id = pub->message_id });
}
break;
}

default:
break;
}
}

/* Active MQTT endpoint: HTTPS provision when valid, else compile-time defaults. */
static const char *mt_mqtt_host(void)
{
	return mt_https_mqtt_cfg.valid ? mt_https_mqtt_cfg.host : MT_MQTT_HOST;
}

static uint16_t mt_mqtt_port(void)
{
	return mt_https_mqtt_cfg.valid ? mt_https_mqtt_cfg.port : (uint16_t)MT_MQTT_PORT;
}

static const char *mt_mqtt_client_id(void)
{
	return mt_https_mqtt_cfg.valid ? mt_https_mqtt_cfg.client_id : MT_MQTT_CLIENT_ID;
}

/* Connect to MQTT broker. Returns 0 on success. */
static int mt_mqtt_do_connect(void)
{
struct sockaddr_in *b4 = (struct sockaddr_in *)&mt_mqtt_broker;
const char *host = mt_mqtt_host();
const char *client_id = mt_mqtt_client_id();
uint16_t port = mt_mqtt_port();
int rc;

memset(&mt_mqtt_broker, 0, sizeof(mt_mqtt_broker));
b4->sin_family = AF_INET;
b4->sin_port   = htons(port);

if (zsock_inet_pton(AF_INET, host, &b4->sin_addr) != 1) {
struct zsock_addrinfo hints = { 0 };
struct zsock_addrinfo *res  = NULL;

hints.ai_family   = AF_INET;
hints.ai_socktype = SOCK_STREAM;
rc = zsock_getaddrinfo(host, NULL, &hints, &res);
if (rc != 0 || res == NULL) {
printk("[MT-MQTT] DNS failed: %d\n", rc);
return -ENOENT;
}
b4->sin_addr = net_sin(res->ai_addr)->sin_addr;
zsock_freeaddrinfo(res);
}

memset(&mt_mqtt_client, 0, sizeof(mt_mqtt_client));
mqtt_client_init(&mt_mqtt_client);

mt_mqtt_client.broker           = &mt_mqtt_broker;
mt_mqtt_client.evt_cb           = mt_mqtt_evt_handler;
mt_mqtt_client.client_id.utf8   = (uint8_t *)client_id;
mt_mqtt_client.client_id.size   = strlen(client_id);
mt_mqtt_client.keepalive        = MT_MQTT_KEEPALIVE_S;
mt_mqtt_client.protocol_version = MQTT_VERSION_3_1_1;
mt_mqtt_client.rx_buf           = mt_mqtt_rx_buf;
mt_mqtt_client.rx_buf_size      = sizeof(mt_mqtt_rx_buf);
mt_mqtt_client.tx_buf           = mt_mqtt_tx_buf;
mt_mqtt_client.tx_buf_size      = sizeof(mt_mqtt_tx_buf);

#if defined(CONFIG_MQTT_LIB_TLS)
if (port == 8883U) {
const void *ca_ptr;
size_t ca_len;
const void *cert_ptr;
size_t cert_len;
const void *key_ptr;
size_t key_len;

if (mt_https_mqtt_cfg.certs_valid) {
ca_ptr = mt_https_mqtt_cfg.ca_pem;
/* Match flash/ca_cert.h style: PEM length without trailing NUL. */
ca_len = mt_https_mqtt_cfg.ca_pem_len ? mt_https_mqtt_cfg.ca_pem_len - 1U
				      : 0U;
cert_ptr = mt_https_mqtt_cfg.client_cert_pem;
cert_len = mt_https_mqtt_cfg.client_cert_pem_len
		   ? mt_https_mqtt_cfg.client_cert_pem_len - 1U
		   : 0U;
key_ptr = mt_https_mqtt_cfg.private_key_pem;
key_len = mt_https_mqtt_cfg.private_key_pem_len
		  ? mt_https_mqtt_cfg.private_key_pem_len - 1U
		  : 0U;
printk("[MT-MQTT] Using HTTPS-provisioned PEMs\n");
} else {
ca_ptr = ca_pem;
ca_len = ca_pem_len;
cert_ptr = client_cert_pem;
cert_len = client_cert_pem_len;
key_ptr = PRIVATE_KEY;
key_len = strlen(PRIVATE_KEY);
printk("[MT-MQTT] Using flash PEMs (ca_cert.h)\n");
}

/* Replace any prior credentials for this tag before add. */
(void)tls_credential_delete(MT_TLS_SEC_TAG, TLS_CREDENTIAL_CA_CERTIFICATE);
(void)tls_credential_delete(MT_TLS_SEC_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE);
(void)tls_credential_delete(MT_TLS_SEC_TAG, TLS_CREDENTIAL_PRIVATE_KEY);

rc = tls_credential_add(MT_TLS_SEC_TAG,
                        TLS_CREDENTIAL_CA_CERTIFICATE,
                        ca_ptr, ca_len);
if (rc != 0 && rc != -EEXIST) {
printk("[MT-MQTT] CA cert: %d\n", rc);
}
rc = tls_credential_add(MT_TLS_SEC_TAG,
                        TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
                        cert_ptr, cert_len);
if (rc != 0 && rc != -EEXIST) {
printk("[MT-MQTT] Client cert: %d\n", rc);
}
rc = tls_credential_add(MT_TLS_SEC_TAG,
                        TLS_CREDENTIAL_PRIVATE_KEY,
                        key_ptr, key_len);
if (rc != 0 && rc != -EEXIST) {
printk("[MT-MQTT] Private key: %d\n", rc);
}

/*
 * Match original pnet_multi_thread TLS bring-up:
 * ENCRYPT on 8883, peer verify off, and do NOT attach sec_tag_list.
 * Attaching the tag (our Phase 4 change) made mqtt_connect return -22
 * (EINVAL) on this offload stack after TCP connect. PEMs are still
 * provisioned into the credential store for the next mTLS step.
 */
mt_mqtt_client.transport.type                      = MQTT_TRANSPORT_SECURE;
mt_mqtt_client.transport.tls.config.peer_verify   = TLS_PEER_VERIFY_NONE;
mt_mqtt_client.transport.tls.config.cipher_count  = 0;
mt_mqtt_client.transport.tls.config.cipher_list   = NULL;
mt_mqtt_client.transport.tls.config.sec_tag_count = 0;
mt_mqtt_client.transport.tls.config.sec_tag_list  = NULL;
mt_mqtt_client.transport.tls.config.cert_nocopy   = 0;
} else {
mt_mqtt_client.transport.type = MQTT_TRANSPORT_NON_SECURE;
}
#else
mt_mqtt_client.transport.type = MQTT_TRANSPORT_NON_SECURE;
#endif

mt_mqtt_connack_rx = false;
rc = mqtt_connect(&mt_mqtt_client);
if (rc != 0) {
printk("[MT-MQTT] mqtt_connect: %d\n", rc);
return rc;
}

rc = mt_mqtt_wait_flag(&mt_mqtt_connack_rx, 30000);
if (rc != 0 || !mt_mqtt_connected) {
printk("[MT-MQTT] CONNACK timeout\n");
mqtt_disconnect(&mt_mqtt_client, NULL);
return -ETIMEDOUT;
}

printk("[MT-MQTT] Connected to %s:%u (id=%s%s)\n", host, port, client_id,
       mt_https_mqtt_cfg.valid ? ", from HTTPS" : ", defaults");
return 0;
}

static void mt_mqtt_do_disconnect(void)
{
int sock = -1;

mt_mqtt_poll_run = false;

#if defined(CONFIG_MQTT_LIB_TLS)
if (mt_mqtt_client.transport.type == MQTT_TRANSPORT_SECURE) {
sock = mt_mqtt_client.transport.tls.sock;
} else
#endif
if (mt_mqtt_client.transport.type == MQTT_TRANSPORT_NON_SECURE) {
sock = mt_mqtt_client.transport.tcp.sock;
}

if (sock >= 0) {
mqtt_disconnect(&mt_mqtt_client, NULL);
zsock_close(sock);
}

mt_mqtt_connected  = false;
mt_mqtt_connack_rx = false;
mt_mqtt_suback_rx  = false;
mt_mqtt_puback_rx  = false;
memset(&mt_mqtt_client, 0, sizeof(mt_mqtt_client));
}

static int mt_do_subscribe(const char *topic)
{
struct mqtt_topic t = {
.topic = { .utf8 = (uint8_t *)topic, .size = strlen(topic) },
.qos   = MQTT_QOS_1_AT_LEAST_ONCE,
};
struct mqtt_subscription_list sl = {
.list       = &t,
.list_count = 1U,
.message_id = mt_next_msg_id(),
};
int rc;

mt_mqtt_suback_rx = false;
rc = mqtt_subscribe(&mt_mqtt_client, &sl);
if (rc != 0) {
return rc;
}
return mt_mqtt_wait_flag(&mt_mqtt_suback_rx, 10000);
}

static int mt_do_publish(const char *topic, const char *payload)
{
struct mqtt_publish_param p = { 0 };
int rc;

p.message.topic.topic.utf8 = (uint8_t *)topic;
p.message.topic.topic.size = strlen(topic);
p.message.topic.qos        = MQTT_QOS_1_AT_LEAST_ONCE;
p.message.payload.data     = (uint8_t *)payload;
p.message.payload.len      = strlen(payload);
p.message_id               = mt_next_msg_id();

mt_mqtt_puback_rx = false;
rc = mqtt_publish(&mt_mqtt_client, &p);
if (rc != 0) {
return rc;
}
return mt_mqtt_wait_flag(&mt_mqtt_puback_rx, 10000);
}

/* ========================================================================
 * Ping work (customer snippet style): send ping directly from callback.
 * ======================================================================== */
static void mt_ping_work_fn(struct k_work *work);
static void mt_ping_work_fn(struct k_work *work)
{
ARG_UNUSED(work);

if (!mt_mqtt_connected) {
return;
}

int rc = mqtt_ping(&mt_mqtt_client);

if (rc < 0) {
rc = mqtt_disconnect(&mt_mqtt_client, NULL);
printk("[MT-POLL] MQTT PING disconnect: %d\n", rc);
} else {
printk("[MT-POLL] MQTT PING sent\n");
}

k_work_reschedule(&mt_ping_dwork,
                  K_SECONDS(MT_MQTT_PING_INTERVAL_S));
}

/* ========================================================================
 * Thread 1: mt_mqtt_poll (prio 7)
 * Drives MQTT keepalive and poll/input processing.
 * ======================================================================== */
static void mt_mqtt_poll_thread(void *p1, void *p2, void *p3)
{
ARG_UNUSED(p1); ARG_UNUSED(p2); ARG_UNUSED(p3);

printk("[MT-POLL] MQTT poll thread started\n");

while (1) {
if (!mt_mqtt_poll_run || !mt_mqtt_connected) {
k_msleep(100);
continue;
}

int rc = mt_mqtt_poll_once(1000);
if (rc < 0 && rc != -EAGAIN && rc != -ETIMEDOUT) {
printk("[MT-POLL] Poll error: %d, MQTT may be lost\n", rc);
mt_mqtt_connected = false;
}
}
}

/* ========================================================================
 * Thread 2: mt_publish (prio 8)
 * Every 60s: publishes telemetry to ra6w1_pub.
 * Optional DNS diagnostics can be enabled via MT_ENABLE_PERIODIC_DNS_DIAG.
 * ======================================================================== */
static void mt_publish_thread(void *p1, void *p2, void *p3)
{
ARG_UNUSED(p1); ARG_UNUSED(p2); ARG_UNUSED(p3);

#if MT_ENABLE_PERIODIC_DNS_DIAG
/* Resolve one host per publish cycle to keep DNS load bounded under PS. */
static const char *dns_hosts[] = {
"google.com",
"yahoo.com",
"cloudflare.com",
};
size_t dns_idx = 0;
#endif

printk("[MT-PUB] Publish thread started (interval: %ds)\n",
       MT_PUBLISH_INTERVAL_S);

/* Wait one full interval before first publish */
k_sleep(K_SECONDS(MT_PUBLISH_INTERVAL_S));

while (1) {
if (!mt_mqtt_connected) {
k_sleep(K_SECONDS(5));
continue;
}

/* Build and publish payload */
char payload[128];
snprintk(payload, sizeof(payload),
         "{\"uptime\": %lld, \"wifi_rssi\": %d, \"ps\": %d}",
         k_uptime_get() / 1000, (int)mt_wifi_rssi,
         mt_in_ps ? 1 : 0);

int rc = mt_do_publish(MT_PUB_TOPIC, payload);
if (rc < 0) {
printk("[MT-PUB] Publish error: %d\n", rc);
} else {
printk("[MT-PUB] Published: %s\n", payload);

#if MT_ENABLE_PERIODIC_DNS_DIAG
/* Post-publish DNS resolve of a rotating public host.
 * Forces a fresh UDP query on fd=0 while fd=1 (MQTT) and
 * fd=2 (UDP thread) are also active — 3 concurrent sockets. */
struct zsock_addrinfo hints = { 0 };
struct zsock_addrinfo *res  = NULL;
const char *host = dns_hosts[dns_idx];

dns_idx = (dns_idx + 1U) % (sizeof(dns_hosts) / sizeof(dns_hosts[0]));

hints.ai_family   = AF_INET;
hints.ai_socktype = SOCK_STREAM;
rc = zsock_getaddrinfo(host, "80", &hints, &res);
if (rc == 0 && res != NULL) {
char ip[NET_IPV4_ADDR_LEN];
net_addr_ntop(AF_INET,
              &net_sin(res->ai_addr)->sin_addr,
              ip, sizeof(ip));
printk("[MT-PUB] DNS %s -> %s\n", host, ip);
zsock_freeaddrinfo(res);
} else {
printk("[MT-PUB] DNS %s failed: %d\n", host, rc);
}
#endif
}

k_sleep(K_SECONDS(MT_PUBLISH_INTERVAL_S));
}
}

/* ========================================================================
 * Thread 3: mt_udp (prio 9)
 * Opens a persistent UDP socket (fd=2).
 * Every 30s: sends a probe datagram, waits for echo, logs RTT.
 * Runs concurrently with fd=0 (DNS UDP) and fd=1 (MQTT TCP).
 * ======================================================================== */
static void mt_udp_thread(void *p1, void *p2, void *p3)
{
ARG_UNUSED(p1); ARG_UNUSED(p2); ARG_UNUSED(p3);

printk("[MT-UDP] UDP thread started (target=%s:%d, interval=%ds)\n",
       MT_UDP_TARGET_IP, MT_UDP_TARGET_PORT, MT_UDP_INTERVAL_S);

int sock = -1;
struct sockaddr_in target = {
    .sin_family = AF_INET,
    .sin_port   = htons(MT_UDP_TARGET_PORT),
};
uint32_t seq = 0;

if (zsock_inet_pton(AF_INET, MT_UDP_TARGET_IP, &target.sin_addr) != 1) {
printk("[MT-UDP] Invalid target IP: %s\n", MT_UDP_TARGET_IP);
return;
}

while (1) {
k_sleep(K_SECONDS(MT_UDP_INTERVAL_S));

if (!mt_https_phase_done) {
printk("[MT-UDP] Waiting for HTTPS phase to finish\n");
continue;
}

if (!mt_wifi_connected) {
if (sock >= 0) {
zsock_close(sock);
sock = -1;
printk("[MT-UDP] WiFi down, UDP socket closed\n");
}
printk("[MT-UDP] WiFi not connected, skipping\n");
continue;
}

/* Create/bind socket lazily only after WiFi is up to avoid early boot crashes. */
if (sock < 0) {
struct sockaddr_in local = {
.sin_family      = AF_INET,
.sin_port        = htons(MT_UDP_LOCAL_PORT),
.sin_addr.s_addr = INADDR_ANY,
};
struct timeval tv = { .tv_sec = MT_UDP_RECV_TIMEOUT_S, .tv_usec = 0 };

sock = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
if (sock < 0) {
printk("[MT-UDP] Socket create failed: errno=%d\n", errno);
continue;
}

if (zsock_bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
printk("[MT-UDP] Bind port %d failed: errno=%d\n",
       MT_UDP_LOCAL_PORT, errno);
zsock_close(sock);
sock = -1;
continue;
}

zsock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
printk("[MT-UDP] Socket ready: fd=%d local_port=%d\n",
       sock, MT_UDP_LOCAL_PORT);
}

char msg[64];
snprintk(msg, sizeof(msg), "MT-UDP seq=%u uptime=%llus",
         seq++, k_uptime_get() / 1000);

int64_t t0 = k_uptime_get();

int tx = zsock_sendto(sock, msg, strlen(msg), 0,
                      (struct sockaddr *)&target, sizeof(target));
if (tx < 0) {
printk("[MT-UDP] TX failed: errno=%d\n", errno);
continue;
}
printk("[MT-UDP] TX %d bytes -> %s:%d  \"%s\"\n",
       tx, MT_UDP_TARGET_IP, MT_UDP_TARGET_PORT, msg);

char rxbuf[128];
struct sockaddr_in from;
socklen_t fromlen = sizeof(from);

int rx = zsock_recvfrom(sock, rxbuf, sizeof(rxbuf) - 1, 0,
                        (struct sockaddr *)&from, &fromlen);
if (rx > 0) {
rxbuf[rx] = '\0';
char from_ip[NET_IPV4_ADDR_LEN];
net_addr_ntop(AF_INET, &from.sin_addr,
              from_ip, sizeof(from_ip));
printk("[MT-UDP] RX %d bytes from %s:%d rtt=%lldms  \"%s\"\n",
       rx, from_ip, ntohs(from.sin_port),
       k_uptime_get() - t0, rxbuf);
} else {
printk("[MT-UDP] No response (timeout %ds)\n",
       MT_UDP_RECV_TIMEOUT_S);
}
}
}

/* ========================================================================
 * Thread 0: mt_flow (prio 6)
 * WiFi + MQTT connect/reconnect state machine only.
 * Publish and UDP are handled by dedicated threads.
 * ======================================================================== */
static void mt_flow_thread(void *p1, void *p2, void *p3)
{
ARG_UNUSED(p1); ARG_UNUSED(p2); ARG_UNUSED(p3);
int rc;
int64_t last_host_diag_ms = 0;

printk("\n========== MT CUSTOMER FLOW STARTED ==========\n");
printk("WiFi:    %s\n", MT_WIFI_SSID);
printk("MQTT:    %s:%u (TLS)\n", mt_mqtt_host(), mt_mqtt_port());
printk("Threads: flow | mqtt_poll | publish | udp\n");
printk("==============================================\n\n");

k_sleep(K_SECONDS(8)); /* Boot delay: let AP stabilize */

while (1) {
int64_t loop_now_ms = k_uptime_get();
if (loop_now_ms - last_host_diag_ms >= MT_HOST_DIAG_INTERVAL_MS) {
mt_log_host_diag();
last_host_diag_ms = loop_now_ms;
}

/* ─── Phase 1: WiFi connect ──────────────────────────── */
if (!mt_wifi_connected) {
printk("[MT-FLOW] Phase 1: Connecting WiFi '%s'...\n",
       MT_WIFI_SSID);

if (mt_iface == NULL) {
mt_iface = net_if_get_default();
}
if (mt_iface != NULL && !net_if_is_up(mt_iface)) {
net_if_up(mt_iface);
k_sleep(K_SECONDS(5));
}

k_event_clear(&mt_dhcp_event, 1U);

struct wifi_connect_req_params wp = { 0 };
wp.ssid        = (uint8_t *)MT_WIFI_SSID;
wp.ssid_length = strlen(MT_WIFI_SSID);
wp.psk         = (uint8_t *)MT_WIFI_PSK;
wp.psk_length  = strlen(MT_WIFI_PSK);
wp.channel     = WIFI_CHANNEL_ANY;
wp.band        = WIFI_FREQ_BAND_UNKNOWN;
wp.security    = WIFI_SECURITY_TYPE_WPA_AUTO_PERSONAL;

rc = net_mgmt(NET_REQUEST_WIFI_CONNECT, mt_iface,
              &wp, sizeof(wp));
if (rc != 0 && rc != -EINPROGRESS) {
printk("[MT-FLOW] WiFi connect failed: %d\n", rc);
k_sleep(K_SECONDS(3));
continue;
}

int64_t end = k_uptime_get() + 30000;
while (!mt_wifi_connected && k_uptime_get() < end) {
k_msleep(100);
}
if (!mt_wifi_connected) {
printk("[MT-FLOW] WiFi timeout\n");
k_sleep(K_SECONDS(3));
continue;
}

	k_event_wait(&mt_dhcp_event, 1U, false, K_SECONDS(30));
	printk("[MT-FLOW] Phase 1: WiFi + DHCP OK\n");
	k_msleep(500);
	}

	/* ─── Phase 2–4: HTTPS GET once; parse MQTT cfg + PEMs ─ */
	{
		static bool https_phase1_done;

		if (!https_phase1_done) {
			printk("[MT-FLOW] Phase 4 HTTPS: GET MQTT cfg + certs...\n");
			rc = https_phase1_get(&mt_https_mqtt_cfg);
			if (rc != 0) {
				printk("[MT-FLOW] HTTPS GET failed: %d (MQTT defaults)\n",
				       rc);
			} else if (mt_https_mqtt_cfg.valid) {
				printk("[MT-FLOW] Phase 4 HTTPS: cfg OK %s:%u id=%s certs=%s\n",
				       mt_https_mqtt_cfg.host,
				       mt_https_mqtt_cfg.port,
				       mt_https_mqtt_cfg.client_id,
				       mt_https_mqtt_cfg.certs_valid ? "yes" : "flash");
			} else {
				printk("[MT-FLOW] Phase 4 HTTPS: GET OK, parse miss (defaults)\n");
			}
			https_phase1_done = true;
			mt_https_phase_done = true;
		}
	}

	/* ─── Phase 4: DNS check (MQTT) ──────────────────────── */
printk("[MT-FLOW] Phase 4: DNS resolving %s...\n", mt_mqtt_host());
struct in_addr broker_ip;

if (zsock_inet_pton(AF_INET, mt_mqtt_host(), &broker_ip) != 1) {
struct zsock_addrinfo hints = { 0 };
struct zsock_addrinfo *res = NULL;

hints.ai_family = AF_INET;
rc = zsock_getaddrinfo(mt_mqtt_host(), NULL, &hints, &res);
if (rc != 0 || res == NULL) {
printk("[MT-FLOW] DNS failed, retrying WiFi\n");
mt_wifi_connected = false;
continue;
}
char ip_str[NET_IPV4_ADDR_LEN];
net_addr_ntop(AF_INET, &net_sin(res->ai_addr)->sin_addr,
              ip_str, sizeof(ip_str));
printk("[MT-FLOW] Resolved: %s\n", ip_str);
zsock_freeaddrinfo(res);
} else {
printk("[MT-FLOW] Literal IP, DNS skipped\n");
}

/* ─── Phase 5: MQTT connect ──────────────────────────── */
if (!mt_mqtt_connected) {
printk("[MT-FLOW] Phase 5: MQTT connect %s:%u...\n",
       mt_mqtt_host(), mt_mqtt_port());

mt_mqtt_do_disconnect();
rc = mt_mqtt_do_connect();
if (rc != 0) {
printk("[MT-FLOW] MQTT failed: %d\n", rc);
k_sleep(K_SECONDS(3));
continue;
}

mt_mqtt_poll_run = true;
printk("[MT-FLOW] Phase 5: MQTT connected\n");
}

/* ─── Phase 6: Power Save ────────────────────────────── */
if (!mt_in_ps) {
printk("[MT-FLOW] Phase 6: Enabling Power Save\n");
mt_ps_enable(true);
}

/* ─── Phase 7: Subscribe once ────────────────────────── */
if (!mt_mqtt_subscribed) {
printk("[MT-FLOW] Phase 7: Subscribing '%s'\n",
       MT_SUB_TOPIC);
rc = mt_do_subscribe(MT_SUB_TOPIC);
if (rc == 0) {
mt_mqtt_subscribed = true;
printk("[MT-FLOW] Subscribed OK\n");
} else {
printk("[MT-FLOW] Subscribe failed: %d\n", rc);
}
printk("[MT-FLOW] Steady state:"
       " publish/%ds udp/%ds\n",
       MT_PUBLISH_INTERVAL_S, MT_UDP_INTERVAL_S);
}

/* ─── Steady state: monitor for disconnect ───────────── */
while (mt_wifi_connected && mt_mqtt_connected) {
int64_t steady_now_ms = k_uptime_get();
if (steady_now_ms - last_host_diag_ms >= MT_HOST_DIAG_INTERVAL_MS) {
mt_log_host_diag();
last_host_diag_ms = steady_now_ms;
}
k_sleep(K_SECONDS(1));
}

/* Recovery */
if (!mt_wifi_connected) {
printk("[MT-FLOW] WiFi lost -> Phase 1\n");
mt_mqtt_subscribed = false;
mt_mqtt_poll_run   = false;
k_work_cancel_delayable(&mt_ping_dwork);
if (mt_in_ps) {
mt_ps_enable(false);
}
} else if (!mt_mqtt_connected) {
printk("[MT-FLOW] MQTT lost -> reconnecting\n");
mt_mqtt_subscribed = false;
mt_mqtt_poll_run   = false;
k_work_cancel_delayable(&mt_ping_dwork);
if (mt_in_ps) {
mt_ps_enable(false);
k_msleep(500);
}
}
}
}

/* ========================================================================
 * Application init — auto-starts all 4 threads at boot
 * ======================================================================== */
static int mt_app_init(void)
{
 k_work_init_delayable(&mt_ping_dwork, mt_ping_work_fn);

net_mgmt_init_event_callback(&mt_ipv4_cb, mt_ipv4_handler,
                             NET_EVENT_IPV4_DHCP_BOUND);
net_mgmt_add_event_callback(&mt_ipv4_cb);

net_mgmt_init_event_callback(&mt_wifi_cb, mt_wifi_handler,
                             NET_EVENT_WIFI_CONNECT_RESULT |
                             NET_EVENT_WIFI_DISCONNECT_RESULT);
net_mgmt_add_event_callback(&mt_wifi_cb);

printk("[MT] Event handlers registered\n");

mt_flow_tid = k_thread_create(&mt_flow_data, mt_flow_stack,
              K_THREAD_STACK_SIZEOF(mt_flow_stack),
              mt_flow_thread, NULL, NULL, NULL,
              K_PRIO_PREEMPT(6), 0, K_NO_WAIT);
k_thread_name_set(mt_flow_tid, "mt_flow");

mt_poll_tid = k_thread_create(&mt_poll_data, mt_poll_stack,
              K_THREAD_STACK_SIZEOF(mt_poll_stack),
              mt_mqtt_poll_thread, NULL, NULL, NULL,
              K_PRIO_PREEMPT(7), 0, K_NO_WAIT);
k_thread_name_set(mt_poll_tid, "mt_mqtt_poll");

mt_pub_tid = k_thread_create(&mt_pub_data, mt_pub_stack,
             K_THREAD_STACK_SIZEOF(mt_pub_stack),
             mt_publish_thread, NULL, NULL, NULL,
             K_PRIO_PREEMPT(8), 0, K_NO_WAIT);
k_thread_name_set(mt_pub_tid, "mt_publish");

mt_udp_tid = k_thread_create(&mt_udp_data, mt_udp_stk,
             K_THREAD_STACK_SIZEOF(mt_udp_stk),
             mt_udp_thread, NULL, NULL, NULL,
             K_PRIO_PREEMPT(9), 0, K_NO_WAIT);
k_thread_name_set(mt_udp_tid, "mt_udp");

printk("[MT] 4 threads started: mt_flow | mt_mqtt_poll | mt_publish | mt_udp\n");
return 0;
}

SYS_INIT(mt_app_init, APPLICATION, 91);
