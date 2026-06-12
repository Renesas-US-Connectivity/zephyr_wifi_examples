
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <zephyr/kernel.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/net_if.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(tcp_client, LOG_LEVEL_INF);

#define WIFI_SSID               "SSID"
#define WIFI_PSK                "PASSWORD"
/* TCP server configuration */
#define SERVER_IP                   "192.168.50.243"
#define SERVER_PORT                 10001

#define TX_MESSAGE_LEN_MAX  64
#define RX_MESSAGE_LEN_MAX  64

static int tcp_fd = -1;

static int wifi_ps_set(struct net_if *iface, struct wifi_ps_params *p)
{
    int rc = net_mgmt(NET_REQUEST_WIFI_PS, iface, p, sizeof(*p));

    if (rc)
    {
        LOG_INF("NET_REQUEST_WIFI_PS failed type=%d rc=%d", p->type, rc);
    }
    return rc;
}

static int wifi_ps_state_set(struct net_if *iface, bool enable)
{
    struct wifi_ps_params p = {0};

    p.type = WIFI_PS_PARAM_STATE;
    p.enabled = enable ? WIFI_PS_ENABLED : WIFI_PS_DISABLED;

    return wifi_ps_set(iface, &p);
}

static void print_wifi_status(struct wifi_iface_status *status)
{
    LOG_INF("wifi_iface_status - state: %s", wifi_state_txt(status->state));
    LOG_INF("wifi_iface_status - ssid: %s", status->ssid);
    LOG_INF("wifi_iface_status - rssi: %d", status->rssi);
}

int main(void)
{
    struct net_if *iface = net_if_get_wifi_sta();
    struct wifi_connect_req_params config = {0};
    struct in_addr *if_addr;
    int s_cnt = 0;

    if (!iface) {
        LOG_ERR("No Wi-Fi interface found");
        return 0;
    }

    config.ssid = (const uint8_t *)WIFI_SSID;
    config.ssid_length = strlen(WIFI_SSID);
    config.psk = (const uint8_t *)WIFI_PSK;
    config.psk_length = strlen(WIFI_PSK);
    config.security = WIFI_SECURITY_TYPE_PSK;
    config.band = WIFI_FREQ_BAND_2_4_GHZ;

    k_msleep(1000);

    LOG_INF("Waiting in idle state for 10seconds");
    k_msleep(10000);
    
    LOG_INF("Connecting to Wi-Fi...");
    if (net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &config, sizeof(config))) {
        LOG_ERR("Connect request failed");
        return 0;
    }

    LOG_INF("Waiting for IP address...");
    while (1) {
        if_addr = net_if_ipv4_get_global_addr(iface, NET_ADDR_PREFERRED);
        if (if_addr) {
            char buf[NET_IPV4_ADDR_LEN];
            LOG_INF("IP Assigned: %s", net_addr_ntop(AF_INET, if_addr, buf, sizeof(buf)));
            break;
        }
        k_msleep(1000);
    }

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        LOG_ERR("Socket failed: %d", errno);
        return 0;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    LOG_INF("Connecting to server %s:%d...", SERVER_IP, SERVER_PORT);
    if (connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        LOG_ERR("Connect failed: %d. Check if server is running!", errno);
        close(fd);
        return 0;
    }

    LOG_INF("TCP Connection Successful!");
  
    char tx[TX_MESSAGE_LEN_MAX];
    char rx[RX_MESSAGE_LEN_MAX];

    for (uint32_t seq = 0; seq < 3; seq++) {
        snprintf(tx, sizeof(tx), "ACTIVE msg %u", (unsigned)seq);
        send(fd, tx, strlen(tx), 0);
    }

    LOG_INF("Entering DPM power save (application-managed)...");
    (void)wifi_ps_state_set(iface, true);
    LOG_INF("Host waiting 10s while RA sleeps...");
    k_sleep(K_SECONDS(10));

while (1)
{
    /* enable both macros to test send and recv in a loop 
*/
#if 1
/* Code to Test send alone continously in a loop
* enable the macro to test send alone in a loop 
*/
    printf("-----driver handles wakeup GPIO-----\n");
    k_msleep(1000);
    char tx_pkt[10] = "DATA_10B";
    char rx_buf[RX_MESSAGE_LEN_MAX];
    while (s_cnt < 3)
    {
        int s_ret = send(fd, tx_pkt, 10, 0);
        if (s_ret < 0) {
            //send(fd, tx_pkt, 10, 0);
            s_cnt++;
            LOG_ERR("Send failed: %d", errno);
        } else {
            s_cnt = 0;
            LOG_INF("Sent 10 bytes");
            break;
        }    
    }
#endif
#if 0
/* Code to Test recv alone continously in a loop
* enable the macro to test recv alone in a loop 
*/
    
    /* RX validation path: wait briefly for inbound data and recv it. */
    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };

    int p_ret = poll(&pfd, 1, 1500);
    if (p_ret < 0) {
        LOG_ERR("poll failed: %d", errno);
    } else if (p_ret == 0) {
        LOG_INF("RX poll timeout (no data)");
    } else {
        if (pfd.revents & POLLIN) {
            int r_ret = recv(fd, rx_buf, sizeof(rx_buf) - 1, 0);
            if (r_ret > 0) {
                rx_buf[r_ret] = '\0';
                LOG_INF("RX %d bytes: %s", r_ret, rx_buf);
            } else if (r_ret == 0) {
                LOG_INF("Server closed connection");
                break;
            } else {
                LOG_ERR("recv failed: %d", errno);
            }
        } else {
            /* Non-data wakeups can happen around DPM transitions; do not treat as fatal. */
            LOG_INF("RX poll wake without POLLIN, revents=0x%x", pfd.revents);
        }
    }

#endif  
//k_msleep(2000);
    (void)wifi_ps_state_set(iface, true);
    LOG_INF("PS mode is application-managed");
    k_msleep(10000);

}
return 0;
}