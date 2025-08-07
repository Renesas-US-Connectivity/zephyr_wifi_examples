/*
 * Copyright (c) 2025 Renesas Electronics Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/net_if.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(main, LOG_LEVEL_DBG);

/* Wi-Fi network configuration */
#define WIFI_SSID					"TP-Link_1218"
#define WIFI_PSK					"74512829"

/* UDP configuration */
#define SERVER_PORT					53704

/* Test message configuration */
#define RX_MESSAGE_LEN_MAX			32

/* Wi-Fi events */
#define WIFI_CALLBACK_EVENT_MASK	(NET_EVENT_WIFI_CONNECT_RESULT | \
									 NET_EVENT_WIFI_DISCONNECT_RESULT)
#define WIFI_EVENT_CONNECT_SUCCESS	BIT(0)
#define WIFI_EVENT_CONNECT_FAILED	BIT(1)
#define WIFI_EVENT_ALL				(WIFI_EVENT_CONNECT_SUCCESS | \
									 WIFI_EVENT_CONNECT_FAILED)

static void print_wifi_status(struct wifi_iface_status *status);

static struct net_mgmt_event_callback cb;

K_EVENT_DEFINE(connect_event);

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

int main(void)
{
	int sfd;
	int bytes_sent;
	int bytes_recvd;
	struct net_if *iface;
    struct in_addr *if_addr;
	struct wifi_connect_req_params config = {0};
	struct wifi_iface_status status = {0};
	struct wifi_version version = {0};
	struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
	socklen_t addr_len;
	uint32_t events;      
	char rx_msg[RX_MESSAGE_LEN_MAX];
    char if_addr_s[NET_IPV4_ADDR_LEN];
	char buf[INET_ADDRSTRLEN];

	LOG_INF("Starting Wi-Fi station UDP server...");

	iface = net_if_get_wifi_sta();
	if (iface == NULL) {
		LOG_INF("Cannot find the Wi-Fi interface");
		return 0;
	}

	net_mgmt_init_event_callback(&cb, wifi_event_handler, 
		WIFI_CALLBACK_EVENT_MASK);
	net_mgmt_add_event_callback(&cb);

	if (net_mgmt(NET_REQUEST_WIFI_VERSION, iface, &version,
			sizeof(version)) == 0) {
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

#if defined (CONFIG_SHIELD_RENESAS_QCIOT_RRQ61051EVZ_MIKROBUS_SPI)
	k_msleep(3000);
#else
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
#endif

	if (net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, iface, &status,
		 sizeof(struct wifi_iface_status))) {
		LOG_INF("Wi-Fi iface status request failed");
		return 0;
	}
	print_wifi_status(&status);

	while (1) {
		sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sfd < 0) {
			LOG_INF("Failed to created socket: %d", sfd);
			return 0;
		}
        LOG_INF("Socket created: %d", sfd);

        server_addr.sin_family = AF_INET;
    	server_addr.sin_port = htons(SERVER_PORT);
   	    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

  	    LOG_INF("Binding socket...");
    	if ((bind(sfd, (struct sockaddr *)&server_addr, sizeof(server_addr))) != 0) {
            LOG_INF("Failed to bind socket: %d", sfd);
    		return 0;
        }

        while(1) {
			/* Wait for client to send us some data */
            bytes_recvd = recvfrom(sfd,
								   rx_msg,
								   sizeof(rx_msg),
								   0,
								   (struct sockaddr *)&client_addr,
								   &addr_len);
            if (bytes_recvd > 0) {
                /* NULL terminate received data */
                if (bytes_recvd < RX_MESSAGE_LEN_MAX) {
                    rx_msg[bytes_recvd] = '\0';
                }

                net_addr_ntop(client_addr.sin_family, 
					&client_addr.sin_addr, buf, sizeof(buf));
                LOG_INF("Received %d bytes from %s:%d - %s", 
					bytes_recvd, buf, client_addr.sin_port, rx_msg);

                /* Echo received data */
                bytes_sent = sendto(sfd,
									rx_msg,
									strlen(rx_msg),
									0,
									(struct sockaddr *)&client_addr,
									sizeof(client_addr));

                if (bytes_sent > 0) {
                    LOG_INF("Sent %d bytes: %s", bytes_sent, rx_msg);
                }
                else {
                    /* Socket error, close */
                    break;
                }
            }
            else {
                if(bytes_recvd == 0) {
                    LOG_INF("socket closed by peer");
                }
                else {
                    LOG_INF("recvfrom error: %d", bytes_recvd);
                }
                /* Don't attempt to send if closed or error */
                break;
            }
        }           

		LOG_INF("Closing socket (%d)..", sfd);

		if (close(sfd) < 0) {
			LOG_INF("Failed to close socket");
			return 0;
		}
        else {
            LOG_INF("Socket successfully closed");
        }
	}

	return 0;
}

static void print_wifi_status(struct wifi_iface_status *status)
{
	LOG_INF("wifi_iface_status - state: %s", wifi_state_txt(status->state));
	LOG_INF("wifi_iface_status - ssid_len: %d", status->ssid_len);
	LOG_INF("wifi_iface_status - ssid: %s", status->ssid);
	LOG_INF("wifi_iface_status - bssid: %x:%x:%x:%x:%x:%x",
		status->bssid[0], status->bssid[1], status->bssid[2],
		status->bssid[3], status->bssid[4], status->bssid[5]);	
	LOG_INF("wifi_iface_status - band: %s", wifi_band_txt(status->band));
	LOG_INF("wifi_iface_status - channel: %d", status->channel);
	LOG_INF("wifi_iface_status - iface_mode: %s", wifi_mode_txt(status->iface_mode));
	LOG_INF("wifi_iface_status - link_mode: %s", wifi_link_mode_txt(status->link_mode));
	LOG_INF("wifi_iface_status - security: %s", wifi_wpa3_enterprise_txt(status->wpa3_ent_type));
	LOG_INF("wifi_iface_status - security: %s", wifi_security_txt(status->security));
	LOG_INF("wifi_iface_status - mfp: %s", wifi_mfp_txt(status->mfp));
	LOG_INF("wifi_iface_status - rssi: %d", status->rssi);
	LOG_INF("wifi_iface_status - dtim_period: %d", status->dtim_period);
	LOG_INF("wifi_iface_status - beacon_interval: %d", status->beacon_interval);
	LOG_INF("wifi_iface_status - twt_capable: %d", status->twt_capable);
	LOG_INF("wifi_iface_status - current_phy_tx_rate: %f", (double)status->current_phy_tx_rate);
}
