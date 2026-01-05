/*
 * Copyright (c) 2023 Lucas Dietrich <ld.adecy@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "creds/creds.h"
#include "net_sample_common.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/dns_resolve.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/net/wifi_mgmt.h>

#if defined(CONFIG_MBEDTLS_MEMORY_DEBUG)
#include <mbedtls/memory_buffer_alloc.h>
#endif
#define USE_WIFI_BSSID_MATCHING 1

/* HTTPS Client Configuration */
#define HTTPS_SERVER "httpbin.org"
#define HTTPS_PORT 443
#define HTTPS_PATH "/get"
#define HTTP_MAX_BUFFER_SIZE 2048
#define HTTP_TIMEOUT K_SECONDS(10)

LOG_MODULE_REGISTER(https, LOG_LEVEL_DBG);

#define TLS_TAG_HTTPS_CA_CERTIFICATE 1

static int setup_credentials(void)
{
    int ret;

    ret = tls_credential_add(TLS_TAG_HTTPS_CA_CERTIFICATE,
                             TLS_CREDENTIAL_CA_CERTIFICATE,
                             ca_cert, ca_cert_len);
    if (ret < 0) {
        LOG_ERR("Failed to add HTTPS CA certificate: %d", ret);
        return ret;
    }

    return 0;
}

/* Wi-Fi network configuration */
#define WIFI_SSID       "ITP-FF"
#define WIFI_PSK        "WiFiNetge@r@1"
#define WIFI_BSSID      "80:cc:9c:51:3f:a3"

/* Wi-Fi connection events */
#define WIFI_EVENT_CONNECT_SUCCESS	BIT(0)
#define WIFI_EVENT_CONNECT_FAILED	BIT(1)
#define WIFI_EVENT_ALL				(WIFI_EVENT_CONNECT_SUCCESS | \
									 WIFI_EVENT_CONNECT_FAILED)
#define NET_EVENT_ALL				(NET_EVENT_IPV4_ADDR_ADD | \
									 NET_EVENT_IPV4_DHCP_BOUND)
#define SCAN_EVENT_DONE			BIT(2)
#define SCAN_EVENT_BSSID_FOUND		BIT(3)

/* Scan result tracking */
static bool bssid_match_found = false;
static struct wifi_scan_result matched_ap = {0};
static uint8_t target_bssid[WIFI_MAC_ADDR_LEN] = {0};
static char configured_ssid[33] = {0};  /* Max SSID length is 32 + null terminator */
static uint8_t configured_ssid_len = 0;
static enum wifi_security_type configured_security = WIFI_SECURITY_TYPE_UNKNOWN;

static struct net_mgmt_event_callback cb;
static struct net_mgmt_event_callback cb1;
static struct net_mgmt_event_callback scan_cb;

K_EVENT_DEFINE(connect_event);
K_EVENT_DEFINE(net_event);
K_EVENT_DEFINE(scan_event);

static void wifi_event_handler(struct net_mgmt_event_callback *cb,
				   uint64_t mgmt_event, struct net_if *iface)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;

	LOG_INF("Wi-Fi event received - layer: %llx code: %llx cmd: %llx status: %d",
		NET_MGMT_GET_LAYER(mgmt_event),
		NET_MGMT_GET_LAYER_CODE(mgmt_event),
		NET_MGMT_GET_COMMAND(mgmt_event),
		status->status);

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

	LOG_INF("NET event received - layer: %llx code: %llx cmd: %llx status: %d",
		NET_MGMT_GET_LAYER(mgmt_event),
		NET_MGMT_GET_LAYER_CODE(mgmt_event),
		NET_MGMT_GET_COMMAND(mgmt_event),
		status->status);

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

static void wifi_scan_result_handler(struct net_mgmt_event_callback *cb,
				     uint64_t mgmt_event, struct net_if *iface)
{
	const struct wifi_scan_result *scan_result =
		(const struct wifi_scan_result *)cb->info;

	if (mgmt_event == NET_EVENT_WIFI_SCAN_RESULT) {
		/* First check BSSID */
		bool bssid_matches = (memcmp(target_bssid, scan_result->mac, WIFI_MAC_ADDR_LEN) == 0);
		if (bssid_matches) {
			/* Log current scan result only if BSSID matches */
			LOG_INF("Scan result - SSID: %.*s, BSSID: %02x:%02x:%02x:%02x:%02x:%02x, Channel: %d, Security: %d",
				scan_result->ssid_length, (const char *)scan_result->ssid,
				scan_result->mac[0], scan_result->mac[1], scan_result->mac[2],
				scan_result->mac[3], scan_result->mac[4], scan_result->mac[5],
				scan_result->channel, scan_result->security);

			/* Only check SSID if BSSID matches */
			bool ssid_matches = (scan_result->ssid_length == configured_ssid_len &&
					     memcmp(configured_ssid, (const char *)scan_result->ssid,
					     configured_ssid_len) == 0);

			/* Check security type */
			bool security_matches = (scan_result->security == configured_security);

			if (ssid_matches && security_matches) {
				if (!bssid_match_found) {
					bssid_match_found = true;
					memcpy(&matched_ap, scan_result, sizeof(struct wifi_scan_result));
					LOG_INF("SUCCESS: BSSID, SSID, and Security Type MATCHED - Target AP found!");
					/* Signal that target AP was found - exit scan wait loop */
					k_event_set(&scan_event, SCAN_EVENT_BSSID_FOUND);
				}
			} else {
				if (!ssid_matches) {
					LOG_WRN("BSSID matched but SSID NOT matched!");
					LOG_WRN("  Configured SSID: %.*s (%d bytes)",
						configured_ssid_len, configured_ssid, configured_ssid_len);
					LOG_WRN("  Scanned SSID: %.*s (%d bytes)",
						scan_result->ssid_length, (const char *)scan_result->ssid,
						scan_result->ssid_length);
				}
				if (!security_matches) {
					LOG_WRN("BSSID and SSID matched but Security Type NOT matched!");
					LOG_WRN("  Configured Security: %d", configured_security);
					LOG_WRN("  Scanned Security: %d", scan_result->security);
				}
			}
		}
	} else if (mgmt_event == NET_EVENT_WIFI_SCAN_DONE) {
		/* Log summary after scan is done */
		if (!bssid_match_found) {
			LOG_WRN("Scan completed: BSSID did not match - Target AP not found");
			k_event_set(&scan_event, SCAN_EVENT_DONE);
		}
	}
}

/* HTTPS Client Implementation */
/**
 * @brief Establish HTTPS connection and retrieve data
 *
 * @param iface Pointer to WiFi network interface
 * @return 0 on success, negative error code on failure
 *
 * This function:
 * - Resolves HTTPS_SERVER hostname via DNS
 * - Creates TLS 1.2 socket
 * - Connects to the HTTPS server
 * - Sends HTTP GET request
 * - Receives and logs response
 * - Properly closes connection
 */
static int https_client_connect_and_request(struct net_if *iface)
{
	int ret;
	int sock = -1;
	struct timeval timeout;
	char request_buffer[HTTP_MAX_BUFFER_SIZE];
	char response_buffer[HTTP_MAX_BUFFER_SIZE];
	int bytes_sent, bytes_recv;
	struct sockaddr_in server_addr;
	struct zsock_addrinfo hints = {0};
	struct zsock_addrinfo *res = NULL;

	LOG_INF("Starting HTTPS client connection to %s:%d", HTTPS_SERVER, HTTPS_PORT);

	/* DNS Resolution */
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	ret = zsock_getaddrinfo(HTTPS_SERVER, "443", &hints, &res);
	if (ret < 0) {
		LOG_ERR("DNS resolution failed for %s: %d", HTTPS_SERVER, ret);
		return -EHOSTUNREACH;
	}

	if (res == NULL) {
		LOG_ERR("No resolution results for %s", HTTPS_SERVER);
		return -EHOSTUNREACH;
	}

	/* Create socket with TLS protocol */
	sock = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
	if (sock < 0) {
		LOG_INF("TLS socket not supported, trying plain TCP");
		sock = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (sock < 0) {
			LOG_ERR("Failed to create socket: %d", sock);
			zsock_freeaddrinfo(res);
			return -EINVAL;
		}
	} else {
		LOG_INF("TLS socket created successfully");
	}

	/* Set socket timeout */
	timeout.tv_sec = 10;
	timeout.tv_usec = 0;
	ret = zsock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	if (ret < 0) {
		LOG_WRN("Failed to set socket receive timeout: %d", ret);
	}

	ret = zsock_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	if (ret < 0) {
		LOG_WRN("Failed to set socket send timeout: %d", ret);
	}

	/* Setup TLS for socket - for public HTTPS server, use peer verify optional */
	int peer_verify = TLS_PEER_VERIFY_OPTIONAL;

	ret = zsock_setsockopt(sock, SOL_TLS, TLS_PEER_VERIFY, &peer_verify, sizeof(peer_verify));
	if (ret < 0) {
		LOG_WRN("Failed to set HTTPS TLS peer verify: %d", ret);
		/* Continue anyway as this might not be critical */
	}

	ret = zsock_setsockopt(sock, SOL_TLS, TLS_HOSTNAME, HTTPS_SERVER, strlen(HTTPS_SERVER));
	if (ret < 0) {
		LOG_WRN("Failed to set HTTPS TLS hostname: %d", ret);
		/* Continue anyway */
	}

	/* Prepare server address with correct port */
	memset(&server_addr, 0, sizeof(server_addr));
	memcpy(&server_addr, res->ai_addr, res->ai_addrlen);
	server_addr.sin_port = htons(HTTPS_PORT);

	LOG_INF("Connecting to HTTPS server at port %d...", HTTPS_PORT);
	ret = zsock_connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
	if (ret < 0) {
		LOG_ERR("Failed to connect to server: %d", ret);
		zsock_close(sock);
		zsock_freeaddrinfo(res);
		return ret;
	}

	LOG_INF("HTTPS connection established");

	/* Send HTTP GET request */
	snprintf(request_buffer, sizeof(request_buffer),
		 "GET %s HTTP/1.1\r\n"
		 "Host: %s\r\n"
		 "Connection: keep-alive\r\n"
		 "User-Agent: Zephyr-HTTPS-Client/1.0\r\n"
		 "\r\n",
		 HTTPS_PATH, HTTPS_SERVER);

	/* Send HTTP request */
	bytes_sent = zsock_send(sock, request_buffer, strlen(request_buffer), 0);
	if (bytes_sent < 0) {
		LOG_ERR("Failed to send HTTP request: %d", bytes_sent);
		zsock_close(sock);
		zsock_freeaddrinfo(res);
		return bytes_sent;
	}

	LOG_INF("HTTP request sent (%d bytes)", bytes_sent);

	/* Receive response */
	memset(response_buffer, 0, sizeof(response_buffer));
	bytes_recv = zsock_recv(sock, response_buffer, sizeof(response_buffer) - 1, 0);
	if (bytes_recv < 0) {
		LOG_ERR("Failed to receive response: %d", bytes_recv);
		zsock_close(sock);
		zsock_freeaddrinfo(res);
		return bytes_recv;
	}

	LOG_INF("Response received (%d bytes)", bytes_recv);
	LOG_INF("Response:");
	LOG_INF("%s", response_buffer);

	/* Keep connection alive and send periodic keep-alive pings */
	LOG_INF("Connection established - Sending keep-alive pings every 5 seconds");
	int ping_count = 0;

	for (;;) {
		k_sleep(K_SECONDS(5));

		/* Send keep-alive ping (HTTP HEAD request) */
		ping_count++;
		snprintf(request_buffer, sizeof(request_buffer),
			 "HEAD %s HTTP/1.1\r\n"
			 "Host: %s\r\n"
			 "Connection: keep-alive\r\n"
			 "User-Agent: Zephyr-HTTPS-Client/1.0\r\n"
			 "\r\n",
			 HTTPS_PATH, HTTPS_SERVER);

		bytes_sent = zsock_send(sock, request_buffer, strlen(request_buffer), 0);
		if (bytes_sent < 0) {
			LOG_WRN("Keep-alive ping #%d failed: %d", ping_count, bytes_sent);
			break;
		}

		/* Receive keep-alive response */
		memset(response_buffer, 0, sizeof(response_buffer));
		bytes_recv = zsock_recv(sock, response_buffer, sizeof(response_buffer) - 1, 0);
		if (bytes_recv < 0) {
			LOG_WRN("Keep-alive response #%d failed: %d", ping_count, bytes_recv);
			break;
		}

		LOG_INF("Keep-alive ping #%d - Server ACK received (%d bytes)", ping_count, bytes_recv);
		LOG_INF("Client and Server are ALIVE");
	}

	/* Close connection */
	zsock_close(sock);
	zsock_freeaddrinfo(res);

	LOG_INF("HTTPS client completed successfully");
	return 0;
}

/**
 * @brief Main application entry point
 *
 * Orchestrates:
 * - WiFi interface initialization
 * - WiFi scan with BSSID matching
 * - WiFi connection and authentication
 * - DHCP IP address acquisition
 * - TLS credential setup
 * - HTTPS client execution
 */
int main(void)
{
	int ret;
	struct net_if *iface;
	struct wifi_connect_req_params config = {0};
	struct wifi_version version = {0};

	uint32_t events;

	LOG_INF("Starting HTTPS client application...");
	k_msleep(3000);
	iface = net_if_get_wifi_sta();
	if (iface == NULL) {
		LOG_INF("Cannot find the Wi-Fi interface");
		return 0;
	}

	LOG_DBG("iface found");
	net_mgmt_init_event_callback(&cb, wifi_event_handler,
			NET_EVENT_WIFI_CONNECT_RESULT);
	net_mgmt_add_event_callback(&cb);
	net_mgmt_init_event_callback(&cb1, net_event_handler,
			 NET_EVENT_IPV4_ADDR_ADD | NET_EVENT_IPV4_DHCP_BOUND);
	net_mgmt_add_event_callback(&cb1);
	net_mgmt_init_event_callback(&scan_cb, wifi_scan_result_handler,
			NET_EVENT_WIFI_SCAN_RESULT | NET_EVENT_WIFI_SCAN_DONE);
	net_mgmt_add_event_callback(&scan_cb);

	LOG_DBG("callback registered");
	if (net_mgmt(NET_REQUEST_WIFI_VERSION, iface, &version,
			sizeof(version)) == 0) {
		LOG_INF("Wi-Fi Driver Version: %s", version.drv_version);
		LOG_INF("Wi-Fi Firmware Version: %s", version.fw_version);
	}

	/* Prepare connection config */
	config.ssid = (const uint8_t *)WIFI_SSID;
	config.ssid_length = strlen(WIFI_SSID);
	config.psk = (const uint8_t *)WIFI_PSK;
	config.psk_length = strlen(WIFI_PSK);
	config.security = WIFI_SECURITY_TYPE_PSK;
	config.band = WIFI_FREQ_BAND_2_4_GHZ;

	/* Store configured security type for validation */
	configured_security = config.security;

#if USE_WIFI_BSSID_MATCHING
	/* Parse BSSID from string for matching during scan */
	uint8_t configured_bssid[WIFI_MAC_ADDR_LEN];
	sscanf(WIFI_BSSID, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
	       &configured_bssid[0], &configured_bssid[1], &configured_bssid[2],
	       &configured_bssid[3], &configured_bssid[4], &configured_bssid[5]);

	/* Store configured SSID for validation during scan */
	configured_ssid_len = strlen(WIFI_SSID);
	if (configured_ssid_len > 32) {
		LOG_ERR("Configured SSID too long: %d bytes (max 32)", configured_ssid_len);
		return 0;
	}
	strncpy(configured_ssid, WIFI_SSID, sizeof(configured_ssid) - 1);
	configured_ssid[32] = '\0';

	LOG_INF("WiFi Configuration - SSID: %s, BSSID: %s, Security: %d", WIFI_SSID, WIFI_BSSID, configured_security);

	/* Scan for available networks via net_mgmt */
	/* Reset scan results before scanning */
	bssid_match_found = false;
	/* Store target BSSID for matching during scan */
	memcpy(target_bssid, configured_bssid, sizeof(target_bssid));

	struct wifi_scan_params scan_params = {0};
	scan_params.scan_type = WIFI_SCAN_TYPE_ACTIVE;

	if (net_mgmt(NET_REQUEST_WIFI_SCAN, iface, &scan_params,
	             sizeof(struct wifi_scan_params))) {
		LOG_INF("Wi-Fi scan request failed");
		return 0;
	}

	/* Wait for target AP to be found during scan or scan to complete */
	events = k_event_wait(&scan_event,
	                       SCAN_EVENT_BSSID_FOUND | SCAN_EVENT_DONE,
	                       true, K_SECONDS(10));

	if (events & SCAN_EVENT_BSSID_FOUND) {
		/* Target AP found (BSSID and SSID both matched) - proceed with connection */
		LOG_INF("Target AP found during scan (BSSID and SSID matched) - connecting now");
	} else if (events & SCAN_EVENT_DONE) {
		/* Scan completed but target AP not found */
		if (!bssid_match_found) {
		LOG_ERR("ERROR: Target AP not found in scan results!");
		LOG_ERR("  Expected SSID: %s", WIFI_SSID);
		LOG_ERR("  Expected BSSID: %s", WIFI_BSSID);
		LOG_ERR("  Expected Security: %d", configured_security);
		LOG_ERR("Aborting connection attempt");
		return 0;
		}
	} else {
		/* Timeout */
		LOG_ERR("Scan timeout - Target AP not found within timeout period");
		return 0;
	}

	/* Final validation before connecting */
	if (!bssid_match_found) {
		LOG_ERR("CRITICAL ERROR: Target AP validation failed before connection!");
		LOG_ERR("Refusing to connect to mismatched network");
		return 0;
	}

	/* Use channel and BSSID from matched AP */
	config.channel = matched_ap.channel;
	memcpy(config.bssid, matched_ap.mac, WIFI_MAC_ADDR_LEN);

	LOG_INF("Connection parameters verified - attempting WiFi connection");
#else
	/* Use default channel without BSSID matching */
	config.channel = WIFI_CHANNEL_ANY;
#endif

	if (net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &config,
	             sizeof(struct wifi_connect_req_params))) {
		LOG_INF("Wi-Fi connect request failed");
		return 0;
	}
	/* Wait for connection result */
	events = k_event_wait(&connect_event, WIFI_EVENT_ALL, true, K_FOREVER);
	if (events != WIFI_EVENT_CONNECT_SUCCESS) {
		return 0;
	}

	/* Wait for DHCP to get IP address */
	do {
		events = k_event_wait(&net_event, NET_EVENT_ALL, true, K_FOREVER);
		if (events & NET_EVENT_IPV4_DHCP_BOUND) {
			LOG_INF("DHCP lease received!");
			break;
		}
	} while (1);

#if defined (CONFIG_SHIELD_RENESAS_QCIOT_RRQ61051EVZ_PMOD)
	k_msleep(100);
#else
	k_msleep(3000);
#endif

	setup_credentials();

	LOG_INF("Credentials setup completed");

	/* Start HTTPS client application with keep-alive pings */
	LOG_INF("Starting HTTPS client application...");
	ret = https_client_connect_and_request(iface);
	if (ret < 0) {
		LOG_ERR("HTTPS client failed: %d", ret);
		return ret;
	}

	/* Application completed */
	LOG_INF("Application finished");
	return 0;
}
