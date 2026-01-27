 
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
 

#if 1
#define WIFI_SSID        "SSID"
#define WIFI_PSK         "12345678"
 
#define SERVER_IP        "192.168.1.1"
#define SERVER_PORT      10001
#endif

#define TX_MESSAGE_LEN_MAX  64
#define RX_MESSAGE_LEN_MAX  64
#define RX_THREAD_STACK_SIZE 2048
#define RX_THREAD_PRIORITY   5
K_THREAD_STACK_DEFINE(app_rx_stack, RX_THREAD_STACK_SIZE);
static struct k_thread rx_thread;
static int tcp_fd = -1;
struct k_mutex erpc_mutex;

static struct net_mgmt_event_callback cb;

K_EVENT_DEFINE(connect_event);

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
/* Wi-Fi events */
#define WIFI_CALLBACK_EVENT_MASK	(NET_EVENT_WIFI_CONNECT_RESULT | \
									 NET_EVENT_WIFI_DISCONNECT_RESULT)
#define WIFI_EVENT_CONNECT_SUCCESS	BIT(0)
#define WIFI_EVENT_CONNECT_FAILED	BIT(1)
#define WIFI_EVENT_ALL				(WIFI_EVENT_CONNECT_SUCCESS | \
									 WIFI_EVENT_CONNECT_FAILED)
static void print_wifi_status(struct wifi_iface_status *status)
{
    LOG_INF("wifi_iface_status - state: %s", wifi_state_txt(status->state));
    LOG_INF("wifi_iface_status - ssid: %s", status->ssid);
    LOG_INF("wifi_iface_status - rssi: %d", status->rssi);
}
static void wifi_event_handler(struct net_mgmt_event_callback *cb,
				   uint64_t mgmt_event, struct net_if *iface)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;

	LOG_INF("Wi-Fi event - layer: %llx code: %llx cmd: %llx status: %d",
		NET_MGMT_GET_LAYER(mgmt_event), NET_MGMT_GET_LAYER_CODE(mgmt_event),
		NET_MGMT_GET_COMMAND(mgmt_event), status->status);
	
	switch (mgmt_event) {
	case NET_EVENT_WIFI_CONNECT_RESULT:
		if (status->status == 0) {
			LOG_INF("Connected to AP!");
			k_event_set(&connect_event, WIFI_EVENT_CONNECT_SUCCESS);
		} else {
			LOG_INF("Failed to connect to AP!");
			k_event_set(&connect_event, WIFI_EVENT_CONNECT_FAILED);
		}
		break;
	case NET_EVENT_WIFI_DISCONNECT_RESULT:
		LOG_INF("Disconnected from AP!");
		break;
	default:
		break;
	}
}
static int wifi_ps_set(struct net_if *iface, struct wifi_ps_params *p)
{
    LOG_INF("Setting Wi-Fi Power Save: type=%d", p->type);
    k_mutex_lock(&erpc_mutex, K_FOREVER);
    int rc = net_mgmt(NET_REQUEST_WIFI_PS, iface, p, sizeof(*p));
    k_mutex_unlock(&erpc_mutex);
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
bool erpc_crc_check() {
  struct wifi_version version = {0};

  if (net_mgmt(NET_REQUEST_WIFI_VERSION, net_if_get_wifi_sta(), &version,
               sizeof(version)) == 0) {
    if (strlen((char *)version.drv_version) > 0) {
      LOG_INF("Wi-Fi Driver Version: %s", version.drv_version);
      return true;
    }
  }

  return false;
}
int main(void)
{
int fd;
	int bytes_sent;
	int bytes_recvd;
	struct net_if *iface;
	struct wifi_connect_req_params config = {0};
	struct wifi_iface_status status = {0};
	struct wifi_version version = {0};
	struct sockaddr_in server_addr;
	uint32_t seq_nbr = 0;
	uint32_t events;
	char tx_msg[TX_MESSAGE_LEN_MAX];
	char rx_msg[RX_MESSAGE_LEN_MAX];
#if defined (CONFIG_ERPC_TRANSPORT_UART)
	struct in_addr *if_addr;
	char if_addr_s[NET_IPV4_ADDR_LEN];
#endif

	LOG_INF("Starting Wi-Fi station TCP client...");
    gpio_wakeup_init(&g_gpio_wakeup_dev);
    k_mutex_init(&erpc_mutex);
    struct wifi_ps_params p = {0};

	iface = net_if_get_wifi_sta();
	p.type = WIFI_PS_PARAM_LISTEN_INTERVAL;
    p.listen_interval = 10;
    wifi_ps_set(iface, &p);
    k_msleep(1000);
	if (iface == NULL) {
		LOG_INF("Cannot find the Wi-Fi interface");
		return 0;
	}

	net_mgmt_init_event_callback(&cb, wifi_event_handler, 
		WIFI_CALLBACK_EVENT_MASK);
	net_mgmt_add_event_callback(&cb);

	if (net_mgmt(NET_REQUEST_WIFI_VERSION, iface, &version,
			sizeof(version)) == 0) {
		if (version.drv_version) {
			LOG_INF("Wi-Fi Driver Version: %s", version.drv_version);
		}
		if (version.fw_version) {
			LOG_INF("Wi-Fi Firmware Version: %s", version.fw_version);
		}
	}

	config.ssid = (const uint8_t *)WIFI_SSID;
	config.ssid_length = strlen(WIFI_SSID);
	config.psk = (const uint8_t *)WIFI_PSK;
	config.psk_length = strlen(WIFI_PSK);
	config.security = WIFI_SECURITY_TYPE_PSK;
	config.channel = WIFI_CHANNEL_ANY;
	config.band = WIFI_FREQ_BAND_2_4_GHZ;

	do {
		LOG_INF("Connecting to network (SSID: %s)", config.ssid);

		if (net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &config,
					sizeof(struct wifi_connect_req_params))) {
			LOG_INF("Wi-Fi connect request failed");
			return 0;
		}

		events = k_event_wait(&connect_event, WIFI_EVENT_ALL, true, K_FOREVER);	
		if (events == WIFI_EVENT_CONNECT_SUCCESS) {
			LOG_INF("Joined network!");
			break;
		}		
	} while (1);

#if defined (CONFIG_ERPC_TRANSPORT_UART)
	do {
		LOG_INF("Waiting for IP address to be assigned...");

		if_addr = net_if_ipv4_get_global_addr(iface, NET_ADDR_PREFERRED);

		if (if_addr) {
			net_addr_ntop(AF_INET, if_addr->s4_addr, if_addr_s, sizeof(if_addr_s));
			LOG_INF("Address: %s", if_addr_s);
		} else {
			k_msleep(1000);
		}		
	} while (if_addr == NULL);
#else
	k_msleep(3000);
#endif

	if (net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, iface, &status,
		 sizeof(struct wifi_iface_status))) {
		LOG_INF("Wi-Fi iface status request failed");
		return 0;
	}
	print_wifi_status(&status);

   fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (fd < 0) {
			LOG_INF("Failed to created socket: %d", fd);
			return 0;
		}

		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(SERVER_PORT);
		server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

		LOG_INF("Connecting to server at: %s %d..", SERVER_IP, SERVER_PORT);

		if (connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
			LOG_INF("Failed to establish connection");
			close(fd);
			return 0;
		}
    	send(fd, "INITIAL_MSG", 11, 0);
    	LOG_INF("Initial message sent. Entering main cycle.");
    	set_low_power_mode(iface, 10, 800);
		int s_cnt = 0;
		k_msleep(10000);
while (1)
{

#if 1
/* Code to Test send alone continously in a loop
* enable the macro to test send alone in a loop 
*/
    k_msleep(10000);
    printf("-----waking up TIN with GPIO-----\n");
    gpio_trigger_wakeup(g_gpio_wakeup_dev);
	while (!erpc_crc_check()) {
         printf("ERPC CRC check failed\n");
         k_sleep(K_SECONDS(1));
    }
	//wifi_ps_state_set(iface, false);
    k_msleep(2000);
    char tx_pkt[10] = "MESSAG_12";
    while (s_cnt < 5)
    {

        k_mutex_lock(&erpc_mutex, K_FOREVER);
        int s_ret = send(fd, tx_pkt, 10, 0);
        k_mutex_unlock(&erpc_mutex);
        if (s_ret < 0) {
            s_ret = send(fd, tx_pkt, 10, 0);
			if (s_ret < 0) {
				LOG_INF("Second send attempt failed: %d", s_ret);
            	s_cnt++;
			}
            //LOG_INF("Send failed: %d", errno);
        } else {
            s_cnt = 0;
            LOG_INF("Sent 10 bytes");
            break;
        }    
		 k_msleep(10);
    }
    //k_msleep(2000);
    LOG_INF("Re-enabling PS mode");
	while (erpc_wifi_transport_slave_ready() == 1) {
    }
    //k_mutex_lock(&erpc_mutex, K_FOREVER);
    wifi_ps_state_set(iface, true);
	 //set_low_power_mode(iface, 10, 500);
    //k_mutex_unlock(&erpc_mutex);
#endif  
#if 0
/* Code to Test recv alone continously in a loop
* enable the macro to test recv alone in a loop 
*/
    char rx_buf[RX_MESSAGE_LEN_MAX];
    printf("--- check gpio state\n---");
    int cnt = 0;
    /*while (erpc_wifi_transport_slave_ready() != 1) {
        if (cnt != 1)
        {
            printf("Waiting for slave_ready to go high...\n");
            cnt = 1;    
        }
    }*/
	while (!erpc_wifi_transport_slave_ready()) {
    	//k_msleep(1);
		 if (cnt != 1)
        {
            printf("Waiting for slave_ready to go high...\n");
            cnt = 1;    
        }
	}
	//wifi_ps_state_set(iface, false);
	while (!erpc_crc_check()) {
         printf("ERPC CRC check failed\n");
         k_sleep(K_SECONDS(1));
    }
    k_msleep(2000);
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