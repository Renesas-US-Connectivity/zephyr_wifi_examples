/*
 * Copyright (c) 2025 Renesas Electronics Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/wifi_mgmt.h>

#include <zephyr/logging/log.h>
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

static void print_wifi_status(struct wifi_iface_status *status);

static struct net_mgmt_event_callback cb;
static struct net_mgmt_event_callback cb1;

K_EVENT_DEFINE(connect_event);
K_EVENT_DEFINE(net_event);

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
  case NET_EVENT_IPV6_ADDR_ADD:
    k_event_set(&net_event, NET_EVENT_IPV6_ADDR_ADD);
    LOG_INF("IPv6 address added");
    break;
  default:
    break;
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

  uint32_t events;

  char if_addr_s[NET_IPV4_ADDR_LEN];

  LOG_INF("Starting Wi-Fi station MQTT client...");

  iface = net_if_get_wifi_sta();
  if (iface == NULL) {
    LOG_INF("Cannot find the Wi-Fi interface");
    return 0;
  }

  net_mgmt_init_event_callback(&cb, wifi_event_handler,
                               NET_EVENT_WIFI_CONNECT_RESULT);
  net_mgmt_add_event_callback(&cb);

  net_mgmt_init_event_callback(&cb1, net_event_handler, NET_EVENT_IPV6_ADDR_ADD);
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


#if defined(CONFIG_NET_IPV6)
      LOG_INF("waiting for IP event!");
  events = k_event_wait(&net_event, NET_EVENT_ALL, false, K_FOREVER);
  if (events & NET_EVENT_IPV6_ADDR_ADD) {
    LOG_INF("IPv6 address added!");

    struct in6_addr *if_addr6 =
        net_if_ipv6_get_global_addr(NET_ADDR_PREFERRED, &iface);
    if (if_addr6) {
      char ip6_str[INET6_ADDRSTRLEN];
      net_addr_ntop(AF_INET6, if_addr6, ip6_str, sizeof(ip6_str));
      LOG_INF("IPv6 Address: %s", ip6_str);
    }
  }
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
