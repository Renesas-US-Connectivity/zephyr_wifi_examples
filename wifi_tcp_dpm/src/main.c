
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

LOG_MODULE_REGISTER(tcp_client, LOG_LEVEL_INF);
#define WIFI_SSID               "SSID"
#define WIFI_PSK                "PASSWORD"
/* TCP server configuration */
#define SERVER_IP                   "192.168.1.1"
#define SERVER_PORT                 10001

#define TX_MESSAGE_LEN_MAX  64
#define RX_MESSAGE_LEN_MAX  64

/* GPIO wakeup configuration */
#define GPIO_WAKEUP_NODE			DT_ALIAS(wakeup_gpio)
#define GPIO_WAKEUP_PORT			DT_GPIO_CTLR(GPIO_WAKEUP_NODE, gpios)
#define GPIO_WAKEUP_PIN				DT_GPIO_PIN(GPIO_WAKEUP_NODE, gpios)
#define GPIO_WAKEUP_FLAGS				DT_GPIO_FLAGS(GPIO_WAKEUP_NODE, gpios)
#define WAKEUP_PULSE_DURATION_MS	20	/* Active low for 20 milliseconds */
static void gpio_trigger_wakeup(const struct device *gpio_dev);
void erpc_wifi_gpio_trigger_wakeup(void);
static const struct device *g_gpio_wakeup_dev;
static struct k_timer rx_timer;
static volatile bool rx_pending = false;
static int tcp_fd = -1;
static void print_wifi_status(struct wifi_iface_status *status)
{
    LOG_INF("wifi_iface_status - state: %s", wifi_state_txt(status->state));
    LOG_INF("wifi_iface_status - ssid: %s", status->ssid);
    LOG_INF("wifi_iface_status - rssi: %d", status->rssi);
}
static void rx_timer_cb(struct k_timer *timer)
{
    ARG_UNUSED(timer);
    rx_pending = true;
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
    //gpio_trigger_wakeup(g_gpio_wakeup_dev);
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
 * @brief Trigger wakeup pulse on GPIO (active low for 20ms)
 */
static void gpio_trigger_wakeup(const struct device *gpio_dev)
{
if (gpio_dev == NULL) {
LOG_WRN("GPIO device not initialized");
return;
}

LOG_INF("Triggering wakeup pulse on GPIO pin %d (active low for %dms)", 
GPIO_WAKEUP_PIN, WAKEUP_PULSE_DURATION_MS);

gpio_pin_set(gpio_dev, GPIO_WAKEUP_PIN, 0);
k_msleep(WAKEUP_PULSE_DURATION_MS);

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
    const struct device *gpio_wakeup_dev = NULL;

    if (!iface) {
        LOG_ERR("No Wi-Fi interface found");
        return 0;
    }

    if (gpio_wakeup_init(&gpio_wakeup_dev) != 0) {
        LOG_WRN("Failed to initialize GPIO wakeup pin, continuing without it");
    }
    g_gpio_wakeup_dev = gpio_wakeup_dev;

    config.ssid = (const uint8_t *)WIFI_SSID;
    config.ssid_length = strlen(WIFI_SSID);
    config.psk = (const uint8_t *)WIFI_PSK;
    config.psk_length = strlen(WIFI_PSK);
    config.security = WIFI_SECURITY_TYPE_PSK;
    config.band = WIFI_FREQ_BAND_2_4_GHZ;

    LOG_INF("Setting Listen interval...\n");
    struct wifi_ps_params p = {0};
    p.type = WIFI_PS_PARAM_LISTEN_INTERVAL;
    p.listen_interval = 10;
    wifi_ps_set(iface, &p);
      k_msleep(1000);
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

    LOG_INF("Entering DPM power save (allow RA sleep)...");
    set_low_power_mode(iface, 10, 1000);
    LOG_INF("Host waiting 10s while RA sleeps...");
    k_sleep(K_SECONDS(10));
    
	LOG_INF("--- Demonstrating wakeup pulse ---");
	gpio_trigger_wakeup(gpio_wakeup_dev);
	LOG_INF("--- Wakeup demo complete ---");

    LOG_INF("Restoring Active Mode...");
    k_msleep(5000);
    LOG_INF("Step3: Sending 10 packets x 10 bytes...");
    for (int i = 0; i < 10; i++) {
        char pkt[11];
        memset(pkt, 'A' + (i % 26), 10);
        pkt[10] = '\0';

        int s = send(fd, pkt, 10, 0);
        if (s < 0) {
            LOG_ERR("send failed i=%d errno=%d", i, errno);
            break;
        } else {
            LOG_INF("sent pkt %d (%d bytes)", i, s);
        }
        k_msleep(50);
    }
    k_sleep(K_SECONDS(2));
    LOG_INF("Step4: Re-entering DPM power save (allow RA sleep again)...");
    wifi_ps_state_set(iface, true);
    k_sleep(K_SECONDS(5));
    k_timer_init(&rx_timer, rx_timer_cb, NULL);
while (1) {

    rx_pending = false;
 k_sleep(K_SECONDS(5));
    /* Start timer */
    k_timer_start(&rx_timer, K_SECONDS(10), K_NO_WAIT);

    /* Wait until timer expires */
    while (!rx_pending) {
         LOG_INF("RX: waking RA6W1");
        k_sleep(K_MSEC(100));
    }

    gpio_trigger_wakeup(g_gpio_wakeup_dev);
    k_msleep(1000);
    /* Do recv ONCE */
    int rcvd = recv(fd, rx, sizeof(rx) - 1, 0);

    if (rcvd < 0) {
        LOG_INF("recv failed: %d", errno);
        continue;   /* retry next cycle */
    }

    if (rcvd == 0) {
        LOG_INF("Connection closed by peer");
        break;      /* exit loop permanently */
    }

    /* Successful recv */
    rx[rcvd] = '\0';
    LOG_INF("Received %d bytes: %s", rcvd, rx);

    /* ✅ Break after recv works */
    break;
}
    return 0;
}