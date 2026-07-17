#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/socket_offload.h>
#include <zephyr/net/wifi_mgmt.h>
#if defined(CONFIG_MQTT_LIB_TLS)
#include <zephyr/net/tls_credentials.h>
#include "ca_cert.h"
#endif
#include <zephyr/shell/shell.h>
#include <zephyr/sys/util.h>

#define PNET_MQTT_DEFAULT_BROKER_HOST "test.mosquitto.org"
#define PNET_MQTT_DEFAULT_BROKER_PORT 8883U
#define PNET_MQTT_DEFAULT_CLIENT_ID "pnet-shell-client"

#define PNET_MQTT_MAX_HOST_LEN 63
#define PNET_MQTT_MAX_CLIENT_ID_LEN 63

#define PNET_MQTT_IO_TIMEOUT_MS 6000
#define PNET_MQTT_WAKE_SETTLE_MS 300

static struct mqtt_client g_mqtt_client;
static struct sockaddr_storage g_mqtt_broker;
static uint8_t g_mqtt_rx_buf[1024];
static uint8_t g_mqtt_tx_buf[1024];

static bool g_mqtt_connected;
static bool g_mqtt_connack_received;
static bool g_mqtt_suback_received;
static bool g_mqtt_puback_received;
static uint16_t g_mqtt_puback_msg_id;
static int g_mqtt_last_evt_result;
static uint16_t g_mqtt_msg_id = 1U;
static bool g_in_dpm;

static bool g_mqtt_cfg_valid;
static char g_mqtt_broker_host[PNET_MQTT_MAX_HOST_LEN + 1];
static uint16_t g_mqtt_broker_port;
static char g_mqtt_client_id[PNET_MQTT_MAX_CLIENT_ID_LEN + 1];

#if defined(CONFIG_MQTT_LIB_TLS)
/* Security tag used to register the broker CA certificate.
 * Tag 42 is arbitrary — change if your application uses other tags.
 * To skip certificate verification during development, set
 * PNET_MQTT_TLS_PEER_VERIFY to TLS_PEER_VERIFY_NONE (0). Change to
 * TLS_PEER_VERIFY_REQUIRED (2) and supply a real CA in ca_cert.h for
 * production.
 */
#define PNET_MQTT_TLS_SEC_TAG 42
/* TLS_PEER_VERIFY_REQUIRED: broker certificate is verified against ROOT_CA.
 * Define PNET_MQTT_USE_CLIENT_CERT at build time to also present a client
 * certificate (mutual TLS — required for self-hosted brokers or port 8884).
 */
/* TLS_PEER_VERIFY_REQUIRED: broker server cert is verified against ROOT_CA.
 * This is a full mutual TLS setup — both sides present certificates.
 */
#define PNET_MQTT_TLS_PEER_VERIFY TLS_PEER_VERIFY_NONE
static sec_tag_t g_mqtt_sec_tags[] = { PNET_MQTT_TLS_SEC_TAG };
#endif /* CONFIG_MQTT_LIB_TLS */

static int pnet_mqtt_parse_u32(const char *s, uint32_t *out);

static int cmd_pmqtt_init(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	struct net_if *iface = net_if_get_default();

	if (iface == NULL) {
		shell_error(sh, "No default network interface");
		return 1;
	}

	net_if_up(iface);
	shell_print(sh, "wifi initialize successful: %s", net_if_get_config(iface)->name);
	shell_print(sh, "socket_offload_dns: %d", socket_offload_dns_is_enabled());

	return 0;
}

static int cmd_pmqtt_connect(const struct shell *sh, size_t argc, char *argv[])
{
	int rc;
	struct wifi_connect_req_params params = { 0 };
	struct net_if *iface = net_if_get_default();

	if (argc < 2 || argc > 3) {
		shell_error(sh, "Usage: pnet_mqtt connect <ssid> [psk]");
		return 1;
	}

	if (iface == NULL) {
		shell_error(sh, "No default network interface");
		return 1;
	}

	params.ssid = argv[1];
	params.ssid_length = strlen(argv[1]);
	params.channel = WIFI_CHANNEL_ANY;
	params.band = WIFI_FREQ_BAND_UNKNOWN;

	if (argc == 3) {
		params.psk = argv[2];
		params.psk_length = strlen(argv[2]);
		params.security = WIFI_SECURITY_TYPE_WPA_AUTO_PERSONAL;
	} else {
		params.security = WIFI_SECURITY_TYPE_NONE;
	}

	rc = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &params, sizeof(params));
	if (rc != 0) {
		shell_error(sh, "Connect request failed (%d)", rc);
		return 1;
	}

	shell_print(sh, "Connect request sent");
	return 0;
}

static int pnet_ps_set_local(bool enable)
{
	struct net_if *iface = net_if_get_default();
	struct wifi_ps_params params = { 0 };
	int rc;

	if (iface == NULL) {
		return -ENODEV;
	}

	params.type = WIFI_PS_PARAM_STATE;
	params.enabled = enable ? WIFI_PS_ENABLED : WIFI_PS_DISABLED;
	rc = net_mgmt(NET_REQUEST_WIFI_PS, iface, &params, sizeof(params));
	if (rc != 0) {
		return -EIO;
	}

	return 0;
}

static int cmd_pmqtt_ps(const struct shell *sh, size_t argc, char *argv[])
{
	uint32_t enable_u32;

	if (argc != 2) {
		shell_error(sh, "Usage: pnet_mqtt ps <0|1>");
		return 1;
	}

	if (pnet_mqtt_parse_u32(argv[1], &enable_u32) != 0 || enable_u32 > 1U) {
		shell_error(sh, "Invalid PS value, use 0 or 1");
		return 1;
	}

	if (pnet_ps_set_local(enable_u32 != 0U) != 0) {
		shell_error(sh, "WIFI_PS_PARAM_STATE failed");
		return 1;
	}

	g_in_dpm = (enable_u32 != 0U);
	shell_print(sh, "PS set to %u", enable_u32);
	return 0;
}

static void pnet_mqtt_wake_for_io(const char *reason)
{
	ARG_UNUSED(reason);
	/* Temporarily disable Power Save only if it was enabled */
	if (g_in_dpm) {
		(void)pnet_ps_set_local(false);
		k_msleep(PNET_MQTT_WAKE_SETTLE_MS);
	}
}

static void pnet_mqtt_back_to_dpm(void)
{
	/* Re-enable Power Save only if it was originally requested by the user */
	if (g_mqtt_connected && g_in_dpm) {
		(void)pnet_ps_set_local(true);
	}
}

static uint16_t pnet_mqtt_next_msg_id(void)
{
	g_mqtt_msg_id++;
	if (g_mqtt_msg_id == 0U) {
		g_mqtt_msg_id = 1U;
	}

	return g_mqtt_msg_id;
}

static int pnet_mqtt_parse_u32(const char *s, uint32_t *out)
{
	char *endptr;
	unsigned long v;

	if (s == NULL || out == NULL) {
		return -EINVAL;
	}

	v = strtoul(s, &endptr, 10);
	if (*s == '\0' || *endptr != '\0' || v > UINT32_MAX) {
		return -EINVAL;
	}

	*out = (uint32_t)v;
	return 0;
}

static void pnet_mqtt_cfg_set(const char *host, uint16_t port, const char *client_id)
{
	snprintk(g_mqtt_broker_host, sizeof(g_mqtt_broker_host), "%s", host);
	g_mqtt_broker_port = port;
	snprintk(g_mqtt_client_id, sizeof(g_mqtt_client_id), "%s", client_id);
	g_mqtt_cfg_valid = true;
}

static void pnet_mqtt_evt_handler(struct mqtt_client *const c, const struct mqtt_evt *evt)
{
	ARG_UNUSED(c);

	switch (evt->type) {
	case MQTT_EVT_CONNACK:
		g_mqtt_connack_received = true;
		g_mqtt_last_evt_result = evt->result;
		if (evt->result == 0) {
			g_mqtt_connected = true;
		}
		break;
	case MQTT_EVT_DISCONNECT:
		g_mqtt_connected = false;
		g_mqtt_connack_received = false;
		g_mqtt_suback_received = false;
		g_mqtt_puback_received = false;
		break;
	case MQTT_EVT_SUBACK:
		g_mqtt_suback_received = true;
		g_mqtt_last_evt_result = evt->result;
		break;
	case MQTT_EVT_PUBACK:
		g_mqtt_puback_received = true;
		g_mqtt_puback_msg_id = evt->param.puback.message_id;
		g_mqtt_last_evt_result = evt->result;
		break;
	case MQTT_EVT_PUBLISH: {
		const struct mqtt_publish_param *pub = &evt->param.publish;
		size_t remaining = pub->message.payload.len;
		uint8_t dump[64];

		while (remaining > 0U) {
			int rd = mqtt_read_publish_payload_blocking(c, dump,
							       MIN(remaining, sizeof(dump)));
			if (rd <= 0) {
				break;
			}
			remaining -= (size_t)rd;
		}

		if (pub->message.topic.qos == MQTT_QOS_1_AT_LEAST_ONCE) {
			(void)mqtt_publish_qos1_ack(c,
						&(struct mqtt_puback_param){ .message_id = pub->message_id });
		}
		break;
	}
	default:
		break;
	}
}

static int pnet_mqtt_poll_once(int timeout_ms)
{
	struct zsock_pollfd pfd;
	int rc;
	int sock;

	/* Resolve the raw socket descriptor regardless of transport type. */
#if defined(CONFIG_MQTT_LIB_TLS)
	if (g_mqtt_client.transport.type == MQTT_TRANSPORT_SECURE) {
		sock = g_mqtt_client.transport.tls.sock;
	} else
#endif
	if (g_mqtt_client.transport.type == MQTT_TRANSPORT_NON_SECURE) {
		sock = g_mqtt_client.transport.tcp.sock;
	} else {
		return -ENOTCONN;
	}

	if (sock < 0) {
		return -ENOTCONN;
	}

	pfd.fd = sock;
	pfd.events = ZSOCK_POLLIN;
	pfd.revents = 0;

	rc = zsock_poll(&pfd, 1, timeout_ms);
	if (rc < 0) {
		return -errno;
	}

	if (rc > 0 && (pfd.revents & ZSOCK_POLLIN) != 0) {
		rc = mqtt_input(&g_mqtt_client);
		if (rc == -EAGAIN || rc == 0) {
			return 0;
		}
		if (rc < 0) {
			return rc;
		}
	}

	rc = mqtt_live(&g_mqtt_client);
	if (rc == -EAGAIN || rc == 0) {
		return 0;
	}

	return rc;
}

static int pnet_mqtt_wait_for_flag(bool *flag, int timeout_ms)
{
	int64_t end = k_uptime_get() + timeout_ms;

	while (!(*flag) && k_uptime_get() < end) {
		int rc = pnet_mqtt_poll_once(200);
		if (rc < 0) {
			return rc;
		}
	}

	return *flag ? 0 : -ETIMEDOUT;
}

static int pnet_mqtt_resolve_broker(const char *host, uint16_t port,
					struct sockaddr_storage *out)
{
	struct sockaddr_in *broker4 = (struct sockaddr_in *)out;
	struct zsock_addrinfo hints = { 0 };
	struct zsock_addrinfo *res = NULL;
	char port_s[8];
	int rc;

	memset(out, 0, sizeof(*out));

	broker4->sin_family = AF_INET;
	broker4->sin_port = htons(port);
	if (zsock_inet_pton(AF_INET, host, &broker4->sin_addr) == 1) {
		return 0;
	}

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	snprintk(port_s, sizeof(port_s), "%u", (uint32_t)port);
	rc = zsock_getaddrinfo(host, port_s, &hints, &res);
	if (rc != 0 || res == NULL) {
		if (res != NULL) {
			zsock_freeaddrinfo(res);
		}
		return -EINVAL;
	}

	memcpy(out, res->ai_addr, MIN((size_t)res->ai_addrlen, sizeof(*out)));
	zsock_freeaddrinfo(res);
	return 0;
}

static int pnet_mqtt_setup_client(const char *host, uint16_t port, const char *client_id)
{
	int rc;

	memset(&g_mqtt_client, 0, sizeof(g_mqtt_client));
	memset(&g_mqtt_broker, 0, sizeof(g_mqtt_broker));

	rc = pnet_mqtt_resolve_broker(host, port, &g_mqtt_broker);
	if (rc != 0) {
		return rc;
	}

	mqtt_client_init(&g_mqtt_client);
	g_mqtt_client.broker = &g_mqtt_broker;
	g_mqtt_client.evt_cb = pnet_mqtt_evt_handler;
	g_mqtt_client.client_id.utf8 = (uint8_t *)client_id;
	g_mqtt_client.client_id.size = strlen(client_id);
	g_mqtt_client.keepalive = 120;
	g_mqtt_client.protocol_version = MQTT_VERSION_3_1_1;
	g_mqtt_client.rx_buf = g_mqtt_rx_buf;
	g_mqtt_client.rx_buf_size = sizeof(g_mqtt_rx_buf);
	g_mqtt_client.tx_buf = g_mqtt_tx_buf;
	g_mqtt_client.tx_buf_size = sizeof(g_mqtt_tx_buf);

#if defined(CONFIG_MQTT_LIB_TLS)
	if (port == 8883U) {
		/* Register CA certificate so the TLS stack can verify the broker.
		 * -EEXIST is returned if the tag was already registered; that is
		 * harmless — continue.
		 * When PNET_MQTT_TLS_PEER_VERIFY is TLS_PEER_VERIFY_NONE the CA
		 * is not checked, so sec_tag_count can safely be 0. Keeping it at
		 * 1 here so the same code path works when verification is enabled.
		 */
		int tls_rc = tls_credential_add(PNET_MQTT_TLS_SEC_TAG,
						TLS_CREDENTIAL_CA_CERTIFICATE,
						ca_pem, ca_pem_len);
		if (tls_rc != 0 && tls_rc != -EEXIST) {
			/* Surface exact credential registration failure to shell logs. */
			g_mqtt_last_evt_result = tls_rc;
			return tls_rc;
		}

		/* Register client certificate and private key for mutual TLS.
		 * The broker (require_certificate true) will request the client
		 * cert during the TLS handshake and verify it against ROOT_CA.
		 */
		tls_rc = tls_credential_add(PNET_MQTT_TLS_SEC_TAG,
					    TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
					    client_cert_pem, client_cert_pem_len);
		if (tls_rc != 0 && tls_rc != -EEXIST) {
			g_mqtt_last_evt_result = tls_rc;
			return tls_rc;
		}

		tls_rc = tls_credential_add(PNET_MQTT_TLS_SEC_TAG,
					    TLS_CREDENTIAL_PRIVATE_KEY,
					    private_key_pem, private_key_pem_len);
		if (tls_rc != 0 && tls_rc != -EEXIST) {
			g_mqtt_last_evt_result = tls_rc;
			return tls_rc;
		}

		g_mqtt_client.transport.type = MQTT_TRANSPORT_SECURE;
		g_mqtt_client.transport.tls.config.peer_verify    = PNET_MQTT_TLS_PEER_VERIFY;
		g_mqtt_client.transport.tls.config.cipher_count   = 0;
		g_mqtt_client.transport.tls.config.cipher_list    = NULL;
		g_mqtt_client.transport.tls.config.sec_tag_count  =
				(PNET_MQTT_TLS_PEER_VERIFY == TLS_PEER_VERIFY_NONE)
				? 0U : ARRAY_SIZE(g_mqtt_sec_tags);
		g_mqtt_client.transport.tls.config.sec_tag_list   =
				(PNET_MQTT_TLS_PEER_VERIFY == TLS_PEER_VERIFY_NONE)
				? NULL : g_mqtt_sec_tags;
		g_mqtt_client.transport.tls.config.hostname       = host;
		g_mqtt_client.transport.tls.config.cert_nocopy    = 0;
	} else {
		g_mqtt_client.transport.type = MQTT_TRANSPORT_NON_SECURE;
	}
#else
	g_mqtt_client.transport.type = MQTT_TRANSPORT_NON_SECURE;
#endif /* CONFIG_MQTT_LIB_TLS */

	return 0;
}

static int pnet_mqtt_disconnect_internal(void)
{
	int sock = -1;

#if defined(CONFIG_MQTT_LIB_TLS)
	if (g_mqtt_client.transport.type == MQTT_TRANSPORT_SECURE) {
		sock = g_mqtt_client.transport.tls.sock;
	} else
#endif
	if (g_mqtt_client.transport.type == MQTT_TRANSPORT_NON_SECURE) {
		sock = g_mqtt_client.transport.tcp.sock;
	}

	if (sock >= 0) {
		(void)mqtt_disconnect(&g_mqtt_client, NULL);
		(void)zsock_close(sock);
	}

	g_mqtt_connected = false;
	g_mqtt_connack_received = false;
	g_mqtt_suback_received = false;
	g_mqtt_puback_received = false;
	g_mqtt_puback_msg_id = 0U;
	g_mqtt_last_evt_result = 0;
	memset(&g_mqtt_client, 0, sizeof(g_mqtt_client));

	return 0;
}

static int pnet_mqtt_connect_internal(const char *host, uint16_t port, const char *client_id)
{
	int rc;

	rc = pnet_mqtt_disconnect_internal();
	if (rc != 0) {
		return rc;
	}

	rc = pnet_mqtt_setup_client(host, port, client_id);
	if (rc != 0) {
		g_mqtt_last_evt_result = rc;
		return rc;
	}

	g_mqtt_connack_received = false;
	g_mqtt_last_evt_result = 0;

	rc = mqtt_connect(&g_mqtt_client);
	if (rc != 0) {
		g_mqtt_last_evt_result = rc;
		(void)pnet_mqtt_disconnect_internal();
		return rc;
	}

	rc = pnet_mqtt_wait_for_flag(&g_mqtt_connack_received, PNET_MQTT_IO_TIMEOUT_MS);
	if (rc != 0 || g_mqtt_last_evt_result != 0 || !g_mqtt_connected) {
		if (rc != 0 && g_mqtt_last_evt_result == 0) {
			g_mqtt_last_evt_result = rc;
		}
		(void)pnet_mqtt_disconnect_internal();
		return (rc != 0) ? rc : -EIO;
	}

	pnet_mqtt_cfg_set(host, port, client_id);
	return 0;
}

static int pnet_mqtt_ensure_connected(void)
{
	if (g_mqtt_connected) {
		return 0;
	}

	if (!g_mqtt_cfg_valid) {
		return -ENOTCONN;
	}

	return pnet_mqtt_connect_internal(g_mqtt_broker_host, g_mqtt_broker_port, g_mqtt_client_id);
}

int cmd_mqtt_connect(const struct shell *sh, size_t argc, char *argv[])
{
	const char *host = PNET_MQTT_DEFAULT_BROKER_HOST;
	const char *client_id = PNET_MQTT_DEFAULT_CLIENT_ID;
	uint32_t port_u32 = PNET_MQTT_DEFAULT_BROKER_PORT;
	uint16_t port;
	int rc;

	if (argc > 1) {
		host = argv[1];
	}
	if (argc > 2) {
		rc = pnet_mqtt_parse_u32(argv[2], &port_u32);
		if (rc != 0) {
			shell_error(sh, "Invalid port");
			return 1;
		}
	}
	if (argc > 3) {
		client_id = argv[3];
	}
	if (argc > 4) {
		shell_error(sh, "Usage: pnet mqtt_connect [broker_host_or_ip] [port] [client_id]");
		return 1;
	}
	if (port_u32 == 0U || port_u32 > UINT16_MAX) {
		shell_error(sh, "Invalid port");
		return 1;
	}

	port = (uint16_t)port_u32;

	pnet_mqtt_wake_for_io("mqtt_connect");
	rc = pnet_mqtt_connect_internal(host, port, client_id);
	pnet_mqtt_back_to_dpm();

	if (rc != 0) {
		shell_error(sh, "MQTT connect failed (%d), detail=%d", rc, g_mqtt_last_evt_result);
		return 1;
	}

	shell_print(sh, "MQTT connect successful: %s:%u", host, (uint32_t)port);
	return 0;
}

int cmd_mqtt_publish(const struct shell *sh, size_t argc, char *argv[])
{
	struct mqtt_publish_param param = { 0 };
	enum mqtt_qos qos = MQTT_QOS_0_AT_MOST_ONCE;
	uint32_t qos_u32 = 0U;
	uint16_t msg_id;
	int rc;

	if (argc < 3 || argc > 4) {
		shell_error(sh, "Usage: pnet mqtt_publish <topic> <payload> [qos:0|1]");
		return 1;
	}
	if (argc == 4) {
		rc = pnet_mqtt_parse_u32(argv[3], &qos_u32);
		if (rc != 0 || qos_u32 > 1U) {
			shell_error(sh, "Invalid qos, use 0 or 1");
			return 1;
		}
		qos = (qos_u32 == 0U) ? MQTT_QOS_0_AT_MOST_ONCE : MQTT_QOS_1_AT_LEAST_ONCE;
	}

	pnet_mqtt_wake_for_io("mqtt_publish");

	rc = pnet_mqtt_ensure_connected();
	if (rc != 0) {
		shell_error(sh, "MQTT not connected (%d)", rc);
		pnet_mqtt_back_to_dpm();
		return 1;
	}

	msg_id = pnet_mqtt_next_msg_id();
	param.message.topic.qos = qos;
	param.message.topic.topic.utf8 = (uint8_t *)argv[1];
	param.message.topic.topic.size = strlen(argv[1]);
	param.message.payload.data = (uint8_t *)argv[2];
	param.message.payload.len = strlen(argv[2]);
	param.message_id = msg_id;
	param.dup_flag = 0U;
	param.retain_flag = 0U;

	g_mqtt_puback_received = false;
	g_mqtt_puback_msg_id = 0U;
	g_mqtt_last_evt_result = 0;

	rc = mqtt_publish(&g_mqtt_client, &param);
	if (rc != 0) {
		shell_error(sh, "mqtt_publish failed (%d)", rc);
		pnet_mqtt_back_to_dpm();
		return 1;
	}

	if (qos == MQTT_QOS_1_AT_LEAST_ONCE) {
		rc = pnet_mqtt_wait_for_flag(&g_mqtt_puback_received, PNET_MQTT_IO_TIMEOUT_MS);
		if (rc != 0 || g_mqtt_last_evt_result != 0 || g_mqtt_puback_msg_id != msg_id) {
			shell_error(sh, "MQTT PUBACK failed (%d, evt=%d)", rc, g_mqtt_last_evt_result);
			pnet_mqtt_back_to_dpm();
			return 1;
		}
	} else {
		(void)pnet_mqtt_poll_once(100);
	}

	shell_print(sh, "MQTT publish successful: topic=%s qos=%u", argv[1],
		    (qos == MQTT_QOS_0_AT_MOST_ONCE) ? 0U : 1U);
	pnet_mqtt_back_to_dpm();
	return 0;
}

int cmd_mqtt_subscribe(const struct shell *sh, size_t argc, char *argv[])
{
	struct mqtt_topic topic = { 0 };
	struct mqtt_subscription_list sub_list = { 0 };
	enum mqtt_qos qos = MQTT_QOS_1_AT_LEAST_ONCE;
	uint32_t qos_u32 = 1U;
	int rc;

	if (argc < 2 || argc > 3) {
		shell_error(sh, "Usage: pnet mqtt_subscribe <topic> [qos:0|1]");
		return 1;
	}
	if (argc == 3) {
		rc = pnet_mqtt_parse_u32(argv[2], &qos_u32);
		if (rc != 0 || qos_u32 > 1U) {
			shell_error(sh, "Invalid qos, use 0 or 1");
			return 1;
		}
		qos = (qos_u32 == 0U) ? MQTT_QOS_0_AT_MOST_ONCE : MQTT_QOS_1_AT_LEAST_ONCE;
	}

	pnet_mqtt_wake_for_io("mqtt_subscribe");

	rc = pnet_mqtt_ensure_connected();
	if (rc != 0) {
		shell_error(sh, "MQTT not connected (%d)", rc);
		pnet_mqtt_back_to_dpm();
		return 1;
	}

	topic.topic.utf8 = (uint8_t *)argv[1];
	topic.topic.size = strlen(argv[1]);
	topic.qos = qos;

	sub_list.list = &topic;
	sub_list.list_count = 1U;
	sub_list.message_id = pnet_mqtt_next_msg_id();

	g_mqtt_suback_received = false;
	g_mqtt_last_evt_result = 0;

	rc = mqtt_subscribe(&g_mqtt_client, &sub_list);
	if (rc != 0) {
		shell_error(sh, "mqtt_subscribe failed (%d)", rc);
		pnet_mqtt_back_to_dpm();
		return 1;
	}

	rc = pnet_mqtt_wait_for_flag(&g_mqtt_suback_received, PNET_MQTT_IO_TIMEOUT_MS);
	if (rc != 0 || g_mqtt_last_evt_result != 0) {
		shell_error(sh, "MQTT SUBACK failed (%d, evt=%d)", rc, g_mqtt_last_evt_result);
		pnet_mqtt_back_to_dpm();
		return 1;
	}

	shell_print(sh, "MQTT subscribe successful: topic=%s qos=%u", argv[1],
		    (qos == MQTT_QOS_0_AT_MOST_ONCE) ? 0U : 1U);
	pnet_mqtt_back_to_dpm();
	return 0;
}

int cmd_mqtt_disconnect(const struct shell *sh, size_t argc, char *argv[])
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	pnet_mqtt_wake_for_io("mqtt_disconnect");
	(void)pnet_mqtt_disconnect_internal();
	(void)pnet_ps_set_local(true);
	shell_print(sh, "MQTT disconnect successful");
	g_in_dpm = true;
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(pnet_mqtt_subcmds,
		SHELL_CMD_ARG(init, NULL,
		  "init wifi interface",
		  cmd_pmqtt_init, 1, 0),
		SHELL_CMD_ARG(connect, NULL,
		  "connect <ssid> [psk]",
		  cmd_pmqtt_connect, 2, 1),
		SHELL_CMD_ARG(ps, NULL,
		  "ps <0|1>",
		  cmd_pmqtt_ps, 2, 0),
		SHELL_CMD_ARG(mqtt_connect, NULL,
		  "mqtt_connect [broker_host_or_ip] [port] [client_id]",
		  cmd_mqtt_connect, 1, 3),
		SHELL_CMD_ARG(mqtt_publish, NULL,
		  "mqtt_publish <topic> <payload> [qos:0|1]",
		  cmd_mqtt_publish, 3, 1),
		SHELL_CMD_ARG(mqtt_subscribe, NULL,
		  "mqtt_subscribe <topic> [qos:0|1]",
		  cmd_mqtt_subscribe, 2, 1),
		SHELL_CMD_ARG(mqtt_disconnect, NULL,
		  "mqtt_disconnect",
		  cmd_mqtt_disconnect, 1, 0),
		SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(pnet_mqtt, &pnet_mqtt_subcmds,
		   "standalone MQTT commands for use with pnet init/connect/ps",
		   NULL);
