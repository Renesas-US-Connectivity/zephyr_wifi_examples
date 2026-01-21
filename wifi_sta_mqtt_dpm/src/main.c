/*
 * Copyright (c) 2025 Renesas Electronics Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/wifi_mgmt.h>

LOG_MODULE_REGISTER(main, LOG_LEVEL_DBG);

/* Wi-Fi network configuration */
/* Wi-Fi network configuration */
#define WIFI_SSID "TP-Link_1218"
#define WIFI_PSK "74512829"

/* TCP server configuration */
#define SERVER_IP "192.168.31.224"
#define SERVER_PORT 10001

/* Test message configuration */
#define TX_MESSAGE_LEN_MAX 32
#define RX_MESSAGE_LEN_MAX 32

/* Wi-Fi connection events */
#define WIFI_EVENT_CONNECT_SUCCESS BIT(0)
#define WIFI_EVENT_CONNECT_FAILED BIT(1)
#define WIFI_EVENT_ALL (WIFI_EVENT_CONNECT_SUCCESS | WIFI_EVENT_CONNECT_FAILED)
#define NET_EVENT_ALL (NET_EVENT_IPV4_ADDR_ADD | NET_EVENT_IPV4_DHCP_BOUND)

/* GPIO wakeup configuration */
#define GPIO_WAKEUP_NODE DT_ALIAS(wakeup_gpio)
#define GPIO_WAKEUP_PORT DT_GPIO_CTLR(GPIO_WAKEUP_NODE, gpios)
#define GPIO_WAKEUP_PIN DT_GPIO_PIN(GPIO_WAKEUP_NODE, gpios)
#define GPIO_WAKEUP_FLAGS DT_GPIO_FLAGS(GPIO_WAKEUP_NODE, gpios)
#define WAKEUP_PULSE_DURATION_MS 20 /* Active low for 20 milliseconds */

static void print_wifi_status(struct wifi_iface_status *status);

static struct net_mgmt_event_callback cb;
static struct net_mgmt_event_callback cb1;

K_EVENT_DEFINE(connect_event);
K_EVENT_DEFINE(net_event);

extern int is_subscribed;
void erpc_wifi_gpio_trigger_wakeup(void);
static const struct device *g_gpio_wakeup_dev;
static struct k_timer rx_timer;
static struct k_timer rx_timer;
static volatile bool rx_pending = false;

struct k_mutex erpc_mutex;

static void rx_timer_cb(struct k_timer *timer) {
  ARG_UNUSED(timer);
  rx_pending = true;
}
int wifi_ps_set(struct net_if *iface, struct wifi_ps_params *p) {
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
int wifi_ps_state_set(struct net_if *iface, bool enable) {
  struct wifi_ps_params p = {0};

  p.type = WIFI_PS_PARAM_STATE;
  p.enabled = enable ? WIFI_PS_ENABLED : WIFI_PS_DISABLED;
  p.listen_interval = 20;

  return wifi_ps_set(iface, &p);
}
void erpc_wifi_gpio_trigger_wakeup(void) {
  // gpio_trigger_wakeup(g_gpio_wakeup_dev);
}
static void set_active_mode(struct net_if *iface) {
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

void set_low_power_mode(struct net_if *iface, uint16_t listen_interval,
                        uint32_t timeout_ms) {
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
static int gpio_wakeup_init(const struct device **gpio_dev) {
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
static void gpio_trigger_wakeup(const struct device *gpio_dev) {
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
static void enter_sleep_mode(const struct device *gpio_dev) {
  LOG_INF(
      "Entering sleep mode... Press wakeup button or wait for GPIO trigger");
  LOG_INF("Device will wake up when GPIO pin goes active low for %dms",
          WAKEUP_PULSE_DURATION_MS);

  k_msleep(10000);

  LOG_INF("Exiting sleep mode");
}

static void wifi_event_handler(struct net_mgmt_event_callback *cb,
                               uint64_t mgmt_event, struct net_if *iface) {
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
  default:
    break;
  }
}

static void net_event_handler(struct net_mgmt_event_callback *cb,
                              uint64_t mgmt_event, struct net_if *iface) {
  const struct wifi_status *status = (const struct wifi_status *)cb->info;

  LOG_INF("NET event - layer: %llx code: %llx cmd: %llx status: %d",
          NET_MGMT_GET_LAYER(mgmt_event), NET_MGMT_GET_LAYER_CODE(mgmt_event),
          NET_MGMT_GET_COMMAND(mgmt_event), status->status);

  switch (mgmt_event) {
  case NET_EVENT_IPV4_ADDR_ADD:
    k_event_set(&net_event, NET_EVENT_IPV4_ADDR_ADD);
    LOG_INF("IPv4 address added");
    break;
  case NET_EVENT_IPV4_DHCP_BOUND:
    k_event_set(&net_event, NET_EVENT_IPV4_DHCP_BOUND);
    LOG_INF("DHCP bound - we have an IP address!");
    break;
  default:
    break;
  }
}

static void dhcp_event_handler(struct net_mgmt_event_callback *cb,
                               uint32_t mgmt_event, struct net_if *iface) {
  if (mgmt_event == NET_EVENT_IPV4_DHCP_BOUND) {
    LOG_INF("DHCP bound - we have an IP address!");

    // Get the assigned IP
    struct in_addr *addr =
        net_if_ipv4_get_global_addr(iface, NET_ADDR_PREFERRED);
    if (addr) {
      char ip_str[NET_IPV4_ADDR_LEN];
      net_addr_ntop(AF_INET, addr, ip_str, sizeof(ip_str));
      LOG_INF("IP Address: %s", ip_str);
    }
  }
}

extern int connect_to_broker(void);
int main(void) {
  int fd;
  int bytes_sent;
  int bytes_recvd;
  struct net_if *iface;
  struct in_addr *if_addr;
  struct wifi_connect_req_params config = {0};
  struct wifi_iface_status status = {0};
  struct wifi_version version = {0};
  const struct device *gpio_wakeup_dev = NULL;
  uint32_t events;
  char if_addr_s[NET_IPV4_ADDR_LEN];

  LOG_INF("Starting Wi-Fi station MQTT client...");

  iface = net_if_get_wifi_sta();
  if (iface == NULL) {
    LOG_INF("Cannot find the Wi-Fi interface");
    return 0;
  }

  k_mutex_init(&erpc_mutex);

  if (gpio_wakeup_init(&gpio_wakeup_dev) != 0) {
    LOG_WRN("Failed to initialize GPIO wakeup pin, continuing without it");
  }
  g_gpio_wakeup_dev = gpio_wakeup_dev;

  LOG_INF("Setting Listen interval...\n");
  struct wifi_ps_params p = {0};
  p.type = WIFI_PS_PARAM_LISTEN_INTERVAL;
  p.listen_interval = 20;
  wifi_ps_set(iface, &p);

  k_msleep(1000);

  net_mgmt_init_event_callback(&cb, wifi_event_handler,
                               NET_EVENT_WIFI_CONNECT_RESULT);
  net_mgmt_add_event_callback(&cb);

  net_mgmt_init_event_callback(&cb1, net_event_handler,
                               NET_EVENT_IPV4_ADDR_ADD |
                                   NET_EVENT_IPV4_DHCP_BOUND);
  net_mgmt_add_event_callback(&cb1);

  if (net_mgmt(NET_REQUEST_WIFI_VERSION, iface, &version, sizeof(version)) ==
      0) {
    LOG_INF("Wi-Fi Driver Version: %s", version.drv_version);
    LOG_INF("Wi-Fi Firmware Version: %s", version.fw_version);
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

  do {
    events = k_event_wait(&net_event, NET_EVENT_ALL, true, K_FOREVER);
    if (events & NET_EVENT_IPV4_DHCP_BOUND) {
      LOG_INF("DHCP lease received!");
      break;
    }
  } while (1);

#if defined(CONFIG_SHIELD_RENESAS_QCIOT_RRQ61051EVZ_PMOD)
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

  connect_to_broker();

  while (1) {
    k_msleep(3000);
  }

  return 0;
}

static void print_wifi_status(struct wifi_iface_status *status) {
  LOG_INF("wifi_iface_status - state: %s", wifi_state_txt(status->state));
  LOG_INF("wifi_iface_status - ssid_len: %d", status->ssid_len);
  LOG_INF("wifi_iface_status - ssid: %s", status->ssid);
  LOG_INF("wifi_iface_status - bssid: %x:%x:%x:%x:%x:%x", status->bssid[0],
          status->bssid[1], status->bssid[2], status->bssid[3],
          status->bssid[4], status->bssid[5]);
  LOG_INF("wifi_iface_status - band: %s", wifi_band_txt(status->band));
  LOG_INF("wifi_iface_status - channel: %d", status->channel);
  LOG_INF("wifi_iface_status - iface_mode: %s",
          wifi_mode_txt(status->iface_mode));
  LOG_INF("wifi_iface_status - link_mode: %s",
          wifi_link_mode_txt(status->link_mode));
  LOG_INF("wifi_iface_status - security: %s",
          wifi_wpa3_enterprise_txt(status->wpa3_ent_type));
  LOG_INF("wifi_iface_status - security: %s",
          wifi_security_txt(status->security));
  LOG_INF("wifi_iface_status - mfp: %s", wifi_mfp_txt(status->mfp));
  LOG_INF("wifi_iface_status - rssi: %d", status->rssi);
  LOG_INF("wifi_iface_status - dtim_period: %d", status->dtim_period);
  LOG_INF("wifi_iface_status - beacon_interval: %d", status->beacon_interval);
  LOG_INF("wifi_iface_status - twt_capable: %d", status->twt_capable);
  LOG_INF("wifi_iface_status - current_phy_tx_rate: %f",
          (double)status->current_phy_tx_rate);
}
