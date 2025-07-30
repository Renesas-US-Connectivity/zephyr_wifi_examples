/*
 * Copyright (c) 2025 Renesas Electronics Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/net_if.h>

/* Wi-Fi network configuration */
#define WIFI_SSID					"TP-Link_1218" 
#define WIFI_PSK					"74512829"

/* TCP server configuration */
#define SERVER_IP					"192.168.0.101"
#define SERVER_PORT					53703

/* Test message configuration */
#define TX_MESSAGE_LEN_MAX			32
#define RX_MESSAGE_LEN_MAX			32

/* Wi-Fi connection events */
#define WIFI_EVENT_CONNECT_SUCCESS	BIT(0)
#define WIFI_EVENT_CONNECT_FAILED	BIT(1)
#define WIFI_EVENT_ALL				(WIFI_EVENT_CONNECT_SUCCESS | \
									 WIFI_EVENT_CONNECT_FAILED)

static struct net_mgmt_event_callback cb;

K_EVENT_DEFINE(connect_event);

static void wifi_event_handler(struct net_mgmt_event_callback *cb,
				   uint64_t mgmt_event, struct net_if *iface)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;

	printf("Wi-Fi event - layer: %llx code: %llx cmd: %llx status: %d\n",
		NET_MGMT_GET_LAYER(mgmt_event), NET_MGMT_GET_LAYER_CODE(mgmt_event),
		NET_MGMT_GET_COMMAND(mgmt_event), status->status);
	
	switch (mgmt_event) {
	case NET_EVENT_WIFI_CONNECT_RESULT:
		if (status->status == 0) {
			printf("Connected to AP!\n");
			k_event_set(&connect_event, WIFI_EVENT_CONNECT_SUCCESS);
		} else {
			printf("Failed to connect to AP!\n");
			k_event_set(&connect_event, WIFI_EVENT_CONNECT_FAILED);
		}
		break;
	default:
		break;
	}
}

int main(void)
{
	int fd;
	int bytes_sent;
	int bytes_recvd;
	struct net_if *iface;
    struct in_addr *if_addr;
	struct wifi_connect_req_params config = {0};
	struct wifi_version version = {0};
	struct sockaddr_in server_addr;
	uint32_t seq_nbr = 0;
	uint32_t events;
	char tx_msg[TX_MESSAGE_LEN_MAX];
	char rx_msg[RX_MESSAGE_LEN_MAX];
    char if_addr_s[NET_IPV4_ADDR_LEN];

	printf("Starting Wi-Fi station TCP client...\n");

	iface = net_if_get_wifi_sta();
	if (iface == NULL) {
		printf("Cannot find the Wi-Fi interface\n");
		return 0;
	}

	net_mgmt_init_event_callback(&cb, wifi_event_handler, 
		NET_EVENT_WIFI_CONNECT_RESULT);
	net_mgmt_add_event_callback(&cb);

	if (net_mgmt(NET_REQUEST_WIFI_VERSION, iface, &version,
			sizeof(version)) == 0) {
		printf("Wi-Fi Driver Version: %s\n", version.drv_version);
		printf("Wi-Fi Firmware Version: %s\n", version.fw_version);
	}

	config.ssid = (const uint8_t *)WIFI_SSID;
	config.ssid_length = strlen(WIFI_SSID);
	config.psk = (const uint8_t *)WIFI_PSK;
	config.psk_length = strlen(WIFI_PSK);
	config.security = WIFI_SECURITY_TYPE_PSK;
	config.channel = WIFI_CHANNEL_ANY;
	config.band = WIFI_FREQ_BAND_2_4_GHZ;

	do {
		printf("Connecting to network (SSID: %s)\n", config.ssid);

		if (net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &config,
					sizeof(struct wifi_connect_req_params))) {
			printf("Wi-Fi connect request failed\n");
			return 0;
		}

		events = k_event_wait(&connect_event, WIFI_EVENT_ALL, true, K_FOREVER);	
		if (events == WIFI_EVENT_CONNECT_SUCCESS) {
			printf("Joined network!\n");
			break;
		}		
	} while (1);

#if defined (CONFIG_SHIELD_RENESAS_QCIOT_RRQ61051EVZ_PMOD)
	do {
		printf("Waiting for IP address to be assigned...\n");

		if_addr = net_if_ipv4_get_global_addr(iface, NET_ADDR_PREFERRED);

		if (if_addr) {
			net_addr_ntop(AF_INET, if_addr->s4_addr, if_addr_s, sizeof(if_addr_s));
			printf("Address: %s\n", if_addr_s);
		} else {
			k_msleep(1000);
		}		
	} while (if_addr == NULL);
#else
	k_msleep(3000);
#endif

	while (1) {
		fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (fd < 0) {
			printf("Failed to created socket: %d\n", fd);
			return 0;
		}

		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(SERVER_PORT);
		server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

		printf("Connecting to server at: %s %d..\n", SERVER_IP, SERVER_PORT);

		if (connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
			printf("Failed to establish connection\n");
			close(fd);
			return 0;
		}

		for (seq_nbr = 0; seq_nbr < 4; seq_nbr++) {
			snprintf(tx_msg, TX_MESSAGE_LEN_MAX, "Test message %d..!", seq_nbr);
	
			bytes_sent = send(fd, tx_msg, strlen(tx_msg), 0);
			if (bytes_sent > 0) {
				printf("Sent %d bytes: %s\n", bytes_sent, tx_msg);
			}

			/* Wait for data from the server */
			bytes_recvd = recv(fd, rx_msg, sizeof(rx_msg), 0);
			if (bytes_recvd > 0) {
				/* NULL terminate received data */
				if (bytes_recvd < RX_MESSAGE_LEN_MAX) {
					rx_msg[bytes_recvd] = '\0';
				}
				printf("Received %d bytes: %s\n", bytes_recvd, rx_msg);
			}
		}

		printf("Closing socket (%d)..\n", fd);

		if (close(fd) < 0) {
			printf("Failed to close socket\n");
			return 0;
		}
	}

	return 0;
}
