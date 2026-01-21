/*
 * Copyright (c) 2025 Renesas Electronics Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/wifi_mgmt.h>

LOG_MODULE_REGISTER(dpm, LOG_LEVEL_DBG);

/* GPIO wakeup configuration */
#define GPIO_WAKEUP_NODE DT_ALIAS(wakeup_gpio)
#define GPIO_WAKEUP_PORT DT_GPIO_CTLR(GPIO_WAKEUP_NODE, gpios)
#define GPIO_WAKEUP_PIN DT_GPIO_PIN(GPIO_WAKEUP_NODE, gpios)
#define GPIO_WAKEUP_FLAGS DT_GPIO_FLAGS(GPIO_WAKEUP_NODE, gpios)
#define WAKEUP_PULSE_DURATION_MS 20 /* Active low for 20 milliseconds */

extern struct k_mutex erpc_mutex;

void erpc_wifi_gpio_trigger_wakeup(void);
extern const struct device *g_gpio_wakeup_dev;

extern bool is_ncp_ready;

int wifi_ps_set(struct net_if *iface, struct wifi_ps_params *p);
int wifi_ps_state_set(struct net_if *iface, bool enable);
void gpio_trigger_wakeup(const struct device *gpio_dev);
void set_low_power_mode(struct net_if *iface, uint16_t listen_interval,
                        uint32_t timeout_ms);
bool erpc_crc_check();

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
int gpio_wakeup_init(const struct device **gpio_dev) {
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
void gpio_trigger_wakeup(const struct device *gpio_dev) {
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

void enable_ps_mode() {
  LOG_INF("Set Power save mode ON\n");
  set_low_power_mode(net_if_get_wifi_sta(), 20, 1000);
  /* wait for device to sleep */
  is_ncp_ready = false;
}

void disable_ps_mode() {
  LOG_INF("Restoring Active Mode for ACK...");

  gpio_trigger_wakeup(g_gpio_wakeup_dev);
  /* wait for device to wake up*/
  k_sleep(K_SECONDS(20));
}
