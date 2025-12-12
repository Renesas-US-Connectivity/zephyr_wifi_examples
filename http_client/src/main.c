/*
 * Copyright (c) 2023 Lucas Dietrich <ld.adecy@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <zephyr/net/socket.h>
#include <zephyr/net/dns_resolve.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/data/json.h>
#include <zephyr/random/random.h>
#include <zephyr/logging/log.h>
//#include "net_sample_common.h"


#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/net_if.h>

#include <zephyr/logging/log.h>


LOG_MODULE_REGISTER(http_client, LOG_LEVEL_DBG);

#define SNTP_SERVER "0.pool.ntp.org"

#define AWS_BROKER_PORT CONFIG_AWS_MQTT_PORT

#define MQTT_BUFFER_SIZE 256u
#define APP_BUFFER_SIZE	 4096u

#define MAX_RETRIES	    10u
#define BACKOFF_EXP_BASE_MS 1000u
#define BACKOFF_EXP_MAX_MS  60000u
#define BACKOFF_CONST_MS    5000u

#define TLS_TAG_DEVICE_CERTIFICATE 1
#define TLS_TAG_DEVICE_PRIVATE_KEY 1
#define TLS_TAG_AWS_CA_CERTIFICATE 2

static const sec_tag_t sec_tls_tags[] = {
	TLS_TAG_DEVICE_CERTIFICATE,
	TLS_TAG_AWS_CA_CERTIFICATE,
};

/* Wi-Fi network configuration */
/* Wi-Fi network configuration */
//#define WIFI_SSID				"TP-Link_1218"
//#define WIFI_PSK				"74512829"
#define WIFI_SSID				"ITP-FF"
#define WIFI_PSK				"WiFiNetge@r@1"
/* TCP server configuration */
#define SERVER_IP					"192.168.31.224"
#define SERVER_PORT					10001

/* Test message configuration */
#define TX_MESSAGE_LEN_MAX			32
#define RX_MESSAGE_LEN_MAX			32

/* Wi-Fi connection events */
#define WIFI_EVENT_CONNECT_SUCCESS	BIT(0)
#define WIFI_EVENT_CONNECT_FAILED	BIT(1)
#define WIFI_EVENT_ALL				(WIFI_EVENT_CONNECT_SUCCESS | \
									 WIFI_EVENT_CONNECT_FAILED)
#define NET_EVENT_ALL				(NET_EVENT_IPV4_ADDR_ADD | \
									 NET_EVENT_IPV4_DHCP_BOUND)

static void print_wifi_status(struct wifi_iface_status *status);

static struct net_mgmt_event_callback cb;
static struct net_mgmt_event_callback cb1;

K_EVENT_DEFINE(connect_event);
K_EVENT_DEFINE(net_event);

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
	default:
		break;
	}
}

static void net_event_handler(struct net_mgmt_event_callback *cb,
				   uint64_t mgmt_event, struct net_if *iface)
{
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
                              uint32_t mgmt_event, struct net_if *iface)
{
    if (mgmt_event == NET_EVENT_IPV4_DHCP_BOUND) {
        LOG_INF("DHCP bound - we have an IP address!");
        
        // Get the assigned IP
        struct in_addr *addr = net_if_ipv4_get_global_addr(iface, NET_ADDR_PREFERRED);
        if (addr) {
            char ip_str[NET_IPV4_ADDR_LEN];
            net_addr_ntop(AF_INET, addr, ip_str, sizeof(ip_str));
            LOG_INF("IP Address: %s", ip_str);
        }

    }
}

int http_client(void);

int main(void)
{
	struct net_if *iface;
    struct in_addr *if_addr;
	struct wifi_connect_req_params config = {0};
	struct wifi_iface_status status = {0};
	struct wifi_version version = {0};

	uint32_t events;

	LOG_INF("Starting HTTP client...");
	k_msleep(3000);
	iface = net_if_get_wifi_sta();
	if (iface == NULL) {
		LOG_INF("Cannot find the Wi-Fi interface");
		return 0;
	}

	LOG_INF("iface found\n");
	net_mgmt_init_event_callback(&cb, wifi_event_handler, 
			NET_EVENT_WIFI_CONNECT_RESULT);
	net_mgmt_add_event_callback(&cb);

	net_mgmt_init_event_callback(&cb1, net_event_handler, 
			 NET_EVENT_IPV4_ADDR_ADD | NET_EVENT_IPV4_DHCP_BOUND);
	net_mgmt_add_event_callback(&cb1);

	LOG_INF("callback registered\n");
	if (net_mgmt(NET_REQUEST_WIFI_VERSION, iface, &version,
			sizeof(version)) == 0) {
		LOG_INF("Wi-Fi Driver Version: %s", version.drv_version);
		LOG_INF("Wi-Fi Firmware Version: %s", version.fw_version);
	}

	LOG_INF("version get success\n");
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
			LOG_INF("DHCP lease received!\n");
			break;
		}
	} while (1);

#if defined (CONFIG_SHIELD_RENESAS_QCIOT_RRQ61051EVZ_PMOD)
	do {
		LOG_INF("Waiting for IP address to be assigned...\n");

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

	LOG_INF("waiting to wifi success\n");
	//wait_for_network();

	for (;;) {
		http_client();
		k_sleep(K_SECONDS(10));
	}

	return 0;
}
