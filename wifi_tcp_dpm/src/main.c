 
#include <stdio.h>
#include <string.h>
#include <errno.h>
 
#include <zephyr/kernel.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/net_if.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>
#include <zephyr/posix/fcntl.h>
LOG_MODULE_REGISTER(tcp_client, LOG_LEVEL_INF);
 
#if 0
#define WIFI_SSID               "ITP-FF"
#define WIFI_PSK                "WiFiNetge@r@1"
 
/* TCP server configuration */
#define SERVER_IP                   "172.27.10.28"
#define SERVER_PORT                 10001
#endif
#if 0
#define WIFI_SSID        "Xiaomi_5G"
#define WIFI_PSK         "12345678"
 
#define SERVER_IP        "192.168.28.132"
#define SERVER_PORT      10001
#endif
#if 1
#define WIFI_SSID        "PS_24G"
#define WIFI_PSK         "12345678"
 
#define SERVER_IP        "192.168.50.3"
#define SERVER_PORT      10001
#endif
#if 0
#define WIFI_SSID               "TP-Link_1218"
#define WIFI_PSK                "74512829"
/* TCP server configuration */
#define SERVER_IP                   "192.168.31.224"
#define SERVER_PORT                 10001
#endif
#if 0
#define WIFI_SSID        "SG_JIO"
#define WIFI_PSK         "Subbu@1256"
 
#define SERVER_IP        "192.168.29.208"
#define SERVER_PORT      10001
#endif
#define TX_MESSAGE_LEN_MAX  64
#define RX_MESSAGE_LEN_MAX  64
#define RX_THREAD_STACK_SIZE 2048
#define RX_THREAD_PRIORITY   5
K_THREAD_STACK_DEFINE(app_rx_stack, RX_THREAD_STACK_SIZE);
static struct k_thread rx_thread;
static int tcp_fd = -1;
/* GPIO wakeup configuration */
#define GPIO_WAKEUP_NODE            DT_ALIAS(wakeup_gpio)
#define GPIO_WAKEUP_PORT            DT_GPIO_CTLR(GPIO_WAKEUP_NODE, gpios)
#define GPIO_WAKEUP_PIN             DT_GPIO_PIN(GPIO_WAKEUP_NODE, gpios)
#define GPIO_WAKEUP_FLAGS               DT_GPIO_FLAGS(GPIO_WAKEUP_NODE, gpios)
#define WAKEUP_PULSE_DURATION_MS    20  /* Active low for 5 milliseconds */
static void gpio_trigger_wakeup(const struct device *gpio_dev);
void erpc_wifi_gpio_trigger_wakeup(void);
static const struct device *g_gpio_wakeup_dev;
extern int erpc_wifi_ping(uint32_t timeout_ms);
extern int erpc_wifi_transport_slave_ready(void);
static bool ps_enabled = false;
static bool last_slave_ready = false;
static void print_wifi_status(struct wifi_iface_status *status)
{
    LOG_INF("wifi_iface_status - state: %s", wifi_state_txt(status->state));
    LOG_INF("wifi_iface_status - ssid: %s", status->ssid);
    LOG_INF("wifi_iface_status - rssi: %d", status->rssi);
}
 
static int wifi_ps_set(struct net_if *iface, struct wifi_ps_params *p)
{
    LOG_INF("Setting Wi-Fi Power Save: type=%d", p->type);
    int rc = net_mgmt(NET_REQUEST_WIFI_PS, iface, p, sizeof(*p));
    if (rc) {
        LOG_INF("NET_REQUEST_WIFI_PS failed type=%d rc=%d", p->type, rc);
    } else {
        LOG_INF("Wi-Fi PS set type=%d OK", p->type);
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
void erpc_wifi_gpio_trigger_wakeup(void)
{
   // gpio_trigger_wakeup(g_gpio_wakeup_dev);
}
static void set_active_mode(struct net_if *iface)
{
    LOG_INF("Setting ACTIVE mode (PS disabled, keep RA awake)...");
 
    wifi_ps_state_set(iface, false);
 
    struct wifi_ps_params p = {0};
 
    p.type = WIFI_PS_PARAM_WAKEUP_MODE;
    p.wakeup_mode = WIFI_PS_WAKEUP_MODE_DTIM;
    wifi_ps_set(iface, &p);
    p.type = WIFI_PS_PARAM_TIMEOUT;
    p.timeout_ms = 0;
    wifi_ps_set(iface, &p);
    ps_enabled = false;
}
 
 
static void set_low_power_mode(struct net_if *iface, uint16_t listen_interval, uint32_t timeout_ms)
{
    LOG_INF("Setting LOW POWER mode (DPM)...");
    struct wifi_ps_params p = {0};
    p.type = WIFI_PS_PARAM_WAKEUP_MODE;
    p.wakeup_mode = WIFI_PS_WAKEUP_MODE_LISTEN_INTERVAL;
    wifi_ps_set(iface, &p);
    p.type = WIFI_PS_PARAM_EXIT_STRATEGY;
    p.exit_strategy = WIFI_PS_EXIT_CUSTOM_ALGO;
    wifi_ps_set(iface, &p);
    p.type = WIFI_PS_PARAM_TIMEOUT;
    p.timeout_ms = timeout_ms;
    wifi_ps_set(iface, &p);
    wifi_ps_state_set(iface, true);
    ps_enabled = true;
}
/**
 * @brief Initialize GPIO wakeup pin
 * @return 0 on success, negative on failure
 */
static int gpio_wakeup_init(const struct device **gpio_dev)
{
*gpio_dev = DEVICE_DT_GET(GPIO_WAKEUP_PORT);
 
if (!device_is_ready(*gpio_dev)) {
LOG_ERR("GPIO device not ready");
return -ENODEV;
}
 
int ret = gpio_pin_configure(*gpio_dev, GPIO_WAKEUP_PIN,
 GPIO_OUTPUT_HIGH | GPIO_WAKEUP_FLAGS);
if (ret < 0) {
LOG_ERR("Failed to configure GPIO wakeup pin: %d", ret);
return ret;
}
 
LOG_INF("GPIO wakeup pin initialized (pin: %d)", GPIO_WAKEUP_PIN);
return 0;
}
 
/**
 * @brief Trigger wakeup pulse on GPIO (active low for 5ms)
 */
static void gpio_trigger_wakeup(const struct device *gpio_dev)
{
if (gpio_dev == NULL) {
LOG_WRN("GPIO device not initialized");
return;
}
 
LOG_INF("Triggering wakeup pulse on GPIO pin %d (active low for %dms)",
GPIO_WAKEUP_PIN, WAKEUP_PULSE_DURATION_MS);
 
/* Pull pin LOW (active) */
gpio_pin_set(gpio_dev, GPIO_WAKEUP_PIN, 0);
k_msleep(WAKEUP_PULSE_DURATION_MS);
 
/* Release pin HIGH (inactive) */
gpio_pin_set(gpio_dev, GPIO_WAKEUP_PIN, 1);
k_msleep(WAKEUP_PULSE_DURATION_MS);
 
gpio_pin_set(gpio_dev, GPIO_WAKEUP_PIN, 0);
 
LOG_INF("Wakeup pulse completed");
}
 
/**
 * @brief Enter sleep mode and wait for GPIO wakeup
 */
static void enter_sleep_mode(const struct device *gpio_dev)
{
LOG_INF("Entering sleep mode... Press wakeup button or wait for GPIO trigger");
LOG_INF("Device will wake up when GPIO pin goes active low for %dms",
WAKEUP_PULSE_DURATION_MS);
 
k_msleep(10000);
 
LOG_INF("Exiting sleep mode");
}

int main(void)
{
    struct net_if *iface = net_if_get_wifi_sta();
    struct wifi_connect_req_params config = {0};
    struct in_addr *if_addr;
    int s_cnt = 0;
    if (!iface) return 0;
    gpio_wakeup_init(&g_gpio_wakeup_dev);

    config.ssid = (const uint8_t *)WIFI_SSID;
    config.ssid_length = strlen(WIFI_SSID);
    config.psk = (const uint8_t *)WIFI_PSK;
    config.psk_length = strlen(WIFI_PSK);
    config.security = WIFI_SECURITY_TYPE_PSK;
        struct wifi_ps_params p = {0};
    p.type = WIFI_PS_PARAM_LISTEN_INTERVAL;
    p.listen_interval = 10;
    wifi_ps_set(iface, &p);
      k_msleep(1000);
    LOG_INF("Connecting to Wi-Fi...");
    net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &config, sizeof(config));

    while (!net_if_ipv4_get_global_addr(iface, NET_ADDR_PREFERRED)) {
        k_msleep(1000);
    }

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    if (connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        LOG_ERR("Connect failed");
        return 0;
    }
    tcp_fd = fd;

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    send(fd, "INITIAL_MSG", 11, 0);
    LOG_INF("Initial message sent. Entering main cycle.");
    set_low_power_mode(iface, 10, 2000);
while (1)
{

#if 1
/* Code to Test send alone continously in a loop
* enable the macro to test send alone in a loop 
*/
    k_msleep(10000);
    printf("-----waking up TIN with GPIO-----\n");
    gpio_trigger_wakeup(g_gpio_wakeup_dev);
    wifi_ps_state_set(iface, false);
    k_msleep(2000);
    char tx_pkt[10] = "DATA_10B";
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
    k_msleep(2000);
    LOG_INF("Re-enabling PS mode");
    wifi_ps_state_set(iface, true);
    k_msleep(2000);
#endif  
#if 0
/* Code to Test recv alone continously in a loop
* enable the macro to test recv alone in a loop 
*/
    char rx_buf[RX_MESSAGE_LEN_MAX];
    printf("--- check gpio state\n---");
    int cnt = 0;
    while (erpc_wifi_transport_slave_ready() != 1) {
        if (cnt != 1)
        {
            printf("Waiting for slave_ready to go high...\n");
            cnt = 1;    
        }
    }
    uint32_t start_time = k_uptime_get_32();
    while (k_uptime_get_32() - start_time < 5000) {
            LOG_INF("Polling for data...");
            int r_ret = recv(fd, rx_buf, sizeof(rx_buf) - 1, 0);
            if (r_ret > 0) {
                rx_buf[r_ret] = '\0';
                LOG_INF("[RX] Received: %s", rx_buf);
                break;
            } 
            /*else if (r_ret < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                LOG_ERR("Recv error: %d", errno);
                break;
            }*/
            k_msleep(100);
        }
        wifi_ps_state_set(iface, true);
#endif
}
    return 0;
}