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
#define WIFI_SSID				"TP-Link_1218"
#define WIFI_PSK				"74512829"

/* UDP configuration */
#define SERVER_PORT				53704

/* Test message configuration */
#define RX_MESSAGE_LEN_MAX		32

static struct net_mgmt_event_callback cb;

K_SEM_DEFINE(net_conn_sem, 0, 1);

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
			k_sem_give(&net_conn_sem);
			printf("Connected to AP!\n");
		} else {
			printf("Failed to connect to AP!\n");
		}
		break;
	default:
		break;
	}
}

int main(void)
{
	int sfd;
	int bytes_sent;
	int bytes_recvd;
	struct net_if *iface;
    struct in_addr *if_addr;
	struct wifi_connect_req_params config = {0};
	struct wifi_version version = {0};
	struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;       
	char rx_msg[RX_MESSAGE_LEN_MAX];
    char if_addr_s[NET_IPV4_ADDR_LEN];

	printf("Starting Wi-Fi station UDP server...\n");

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

	printf("Connecting to network (SSID: %s)\n", config.ssid);

	if (net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &config,
				sizeof(struct wifi_connect_req_params))) {
		printf("Wi-Fi connect request failed\n");
		return 0;
	}

	while (k_sem_take(&net_conn_sem, K_MSEC(1000)) != 0) {
		printf("Waiting for network connection..\n");
	}

	printf("Joined network!\n");

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
		sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sfd < 0) {
			printf("Failed to created socket: %d\n", sfd);
			return 0;
		}
        printf("Socket created: %d\n", sfd);

        server_addr.sin_family = AF_INET;
    	server_addr.sin_port = htons(SERVER_PORT);
   	    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

  	    printf("Binding socket...\n");
    	if ((bind(sfd, (struct sockaddr *)&server_addr, sizeof(server_addr))) != 0) {
            printf("Failed to bind socket: %d\n", sfd);
    		return 0;
        }

        while(1) {
			/* Wait for client to send us some data */
            bytes_recvd = recvfrom(sfd, rx_msg, sizeof(rx_msg), 0, &client_addr, sizeof(client_addr));
            if (bytes_recvd > 0) {
                /* NULL terminate received data */
                if (bytes_recvd < RX_MESSAGE_LEN_MAX) {
                    rx_msg[bytes_recvd] = '\0';
                }
                
                // TODO buf is assuming IPV4, extend for IPV6
                char buf[INET_ADDRSTRLEN];
                net_addr_ntop(client_addr.sin_family, &client_addr.sin_addr, buf, sizeof(buf));
                // TODO port bytes are swapped. Fix needed in offload driver
                printf("Received %d bytes from %s:%d : %s\n", bytes_recvd, buf, client_addr.sin_port, rx_msg);

                /* Echo received data */
                bytes_sent = sendto(sfd, rx_msg, strlen(rx_msg), 0, &client_addr, sizeof(client_addr));

                if (bytes_sent > 0) {
                    printf("Sent %d bytes: %s\n", bytes_sent, rx_msg);
                }
                else {
                    /* Socket error, close */
                    break;
                }
            }
            else {
                if(bytes_recvd == 0) {
                    printf("socket closed by peer\n");
                }
                else {
                    printf("recv error=%d\n", bytes_recvd);
                }
                /* Don't attempt to send if closed or error */
                break;
            }
        }           

		printf("Closing socket (%d)..\n", sfd);

		if (close(sfd) < 0) {
			printf("Failed to close socket\n");
			return 0;
		}
        else {
            printf("Socket successfully closed\n");
        }
	}

	return 0;
}
