/*
 * Copyright (c) 2023 Lucas Dietrich <ld.adecy@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "creds/creds.h"
//#include "net_sample_common.h"

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
#include <zephyr/posix/fcntl.h>
#include <mbedtls/ssl_ciphersuites.h>

LOG_MODULE_REGISTER(https, LOG_LEVEL_DBG);

/* Target Configuration */
#define HTTPS_SERVER         "vps-19bb52d9.vps.ovh.net"  /* Server IP/hostname */
#define HTTPS_PORT           443
#define HTTPS_PATH           "/put"

#define USE_HTTPS_SERVER_IP  0              /* 1: Bypass DNS / use IP directly, 0: use DNS */
#define HTTPS_SERVER_IP      "51.68.139.214"

#define USE_TLS_VERIFY_NONE  0              /* 1: Bypass TLS certificate verification, 0: verify */
#define ENABLE_WIFI_DPM      0              /* 1: Enable DPM/PS, 0: Disable */

#define HTTP_MAX_BUFFER_SIZE 2048
#define TLS_TAG_HTTPS_CA_CERTIFICATE 1
#define CLIENT_CERT_TAG 2

/* FSM Mock Definitions from Customer Environment */
enum fsm_msg_id {
	MSG_ID_HTTP_REQUEST_ERROR,
	MSG_ID_HTTP_REQUEST_CONNECT_CHECK,
	MSG_ID_HTTP_REQUEST_CONNECTED,
};

#define FSM_NODE_ID_HTTP_REQUEST 1

struct fsm_msg_header {
	int id;
};

static int last_fsm_msg_id = -1;

static void fsm_node_send_message_id(int msg_id, int node_id)
{
	last_fsm_msg_id = msg_id;
}

/* Customer context structures */
struct http_request_info {
	const char *hostname;
	uint16_t port;
	const sec_tag_t *sec_tag_list;
	size_t sec_tag_count;
};

struct http_request_ctx {
	int socket;
	struct sockaddr endpoint;
	struct http_request_info *current_request;
	int connect_retries;
	int http_status_code;
};

const uint8_t ca_certificate[] =
"-----BEGIN CERTIFICATE-----\n"
"MIICFDCCAbugAwIBAgIUCZCrpIUu1ZmhqPuU6P8tTf64SEMwCgYIKoZIzj0EAwIw\n"
"WDELMAkGA1UEBhMCU0UxDjAMBgNVBAgMBVNrYW5lMQ4wDAYDVQQHDAVNYWxtbzES\n"
"MBAGA1UECgwJQmVzdFN0dWZmMRUwEwYDVQQDDAxCZXN0U3R1ZmYtQ0EwHhcNMjYw\n"
"NzE0MTYzNDI4WhcNMzYwNzExMTYzNDI4WjBYMQswCQYDVQQGEwJTRTEOMAwGA1UE\n"
"CAwFU2thbmUxDjAMBgNVBAcMBU1hbG1vMRIwEAYDVQQKDAlCZXN0U3R1ZmYxFTAT\n"
"BgNVBAMMDEJlc3RTdHVmZi1DQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABC5v\n"
"bJYcsVzl03pmUdwa++sS3vUOZAxua/lx7Gh2Ku0AMQVh6TyFwAr7b+M/NsdtWhxh\n"
"mbz82IpzjYzAyWEGZvSjYzBhMB0GA1UdDgQWBBTI0uTHkM1kWIM1X+tvQN2/2kqC\n"
"0TAfBgNVHSMEGDAWgBTI0uTHkM1kWIM1X+tvQN2/2kqC0TAPBgNVHRMBAf8EBTAD\n"
"AQH/MA4GA1UdDwEB/wQEAwIBhjAKBggqhkjOPQQDAgNHADBEAiBM8FUSkXyNZBUG\n"
"5NeI+PYapnSuswFcQ9943Vn8IocYOQIgAy+Uv2KHsR3+NJ4ky4H4Cb9h4lZjoLR0\n"
"VVJ8Nyquflw=\n"
"-----END CERTIFICATE-----\n";


const uint8_t device_certificate[] =
"-----BEGIN CERTIFICATE-----\n"
"MIICHzCCAcWgAwIBAgIUJpZzrn1VU511RiLZHky/CcmO1lwwCgYIKoZIzj0EAwIw\n"
"WDELMAkGA1UEBhMCU0UxDjAMBgNVBAgMBVNrYW5lMQ4wDAYDVQQHDAVNYWxtbzES\n"
"MBAGA1UECgwJQmVzdFN0dWZmMRUwEwYDVQQDDAxCZXN0U3R1ZmYtQ0EwHhcNMjYw\n"
"NzE0MTY0MjM2WhcNMjgxMDE2MTY0MjM2WjBQMQswCQYDVQQGEwJTRTEOMAwGA1UE\n"
"CAwFU2thbmUxDjAMBgNVBAcMBU1hbG1vMRIwEAYDVQQKDAlCZXN0U3R1ZmYxDTAL\n"
"BgNVBAMMBFIyRDIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ5EExF/2rIQXJT\n"
"1eolep1SMoaTvhh48/3LqmCYqx8m7OxWDijosY7NgEYRSIJlDBrfEh6x4J6ebrPC\n"
"athXnsAzo3UwczAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIw\n"
"DAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUsKY8DGXgK1ZKfswqHl5cBjQ88S8wHwYD\n"
"VR0jBBgwFoAUyNLkx5DNZFiDNV/rb0Ddv9pKgtEwCgYIKoZIzj0EAwIDSAAwRQIh\n"
"AOX8VtcoabXDHiRyBWVFvQx6CLcpMi+Ligof9E6yGRhNAiAeAqtUi1AQDaxSycD1\n"
"QiMapX6syr8HAIXRLf0+0qVrYw==\n"
"-----END CERTIFICATE-----\n";


const uint8_t device_key[] =
"-----BEGIN EC PRIVATE KEY-----\n"
"MHcCAQEEIKooI0AOnF/8L57NdmXDD5vtC2/ol3N73LDCgRZ7uUjnoAoGCCqGSM49\n"
"AwEHoUQDQgAEORBMRf9qyEFyU9XqJXqdUjKGk74YePP9y6pgmKsfJuzsVg4o6LGO\n"
"zYBGEUiCZQwa3xIeseCenm6zwmrYV57AMw==\n"
"-----END EC PRIVATE KEY-----\n";


static int setup_credentials(void)
{
	int ret;

	ret = tls_credential_add(TLS_TAG_HTTPS_CA_CERTIFICATE,
				 TLS_CREDENTIAL_CA_CERTIFICATE,
				 ca_certificate, sizeof(ca_certificate));
	if (ret < 0 && ret != -EEXIST) {
		LOG_ERR("Failed to add CA certificate: %d", ret);
		return ret;
	}

	ret = tls_credential_add(CLIENT_CERT_TAG,
			TLS_CREDENTIAL_SERVER_CERTIFICATE,
			device_certificate,
			sizeof(device_certificate));
	if (ret < 0) {
		LOG_ERR("Failed to register client certificate %d", ret);
		return ret;
	}

	ret = tls_credential_add(CLIENT_CERT_TAG,
			TLS_CREDENTIAL_PRIVATE_KEY,
			device_key,
			sizeof(device_key));
	if (ret < 0) {
		LOG_ERR("Failed to register client private key %d", ret);
		return -1;
	}

	return 0;
}

/* Wi-Fi network configuration */
//#define WIFI_SSID       "TTP-WIFI"
//#define WIFI_PSK        "WiFiNetgearTvm#2"

#define WIFI_SSID       "RenesasMatter"
#define WIFI_PSK        "Matter2023"

#define WIFI_EVENT_CONNECT_SUCCESS  BIT(0)
#define WIFI_EVENT_CONNECT_FAILED   BIT(1)
#define WIFI_EVENT_ALL              (WIFI_EVENT_CONNECT_SUCCESS | WIFI_EVENT_CONNECT_FAILED)

#define EVENT_NET_IPV4_ADDR_ADD     BIT(0)
#define EVENT_NET_IPV4_DHCP_BOUND   BIT(1)
#define NET_EVENT_ALL              (EVENT_NET_IPV4_ADDR_ADD | EVENT_NET_IPV4_DHCP_BOUND)

static void wifi_ps_set(struct net_if *iface, struct wifi_ps_params *params)
{
	if (net_mgmt(NET_REQUEST_WIFI_PS, iface, params, sizeof(*params))) {
		LOG_ERR("Failed to set PS parameters");
	} else {
		LOG_INF("PS parameters set successfully");
	}
}

static void wifi_ps_state_set(struct net_if *iface, bool enable)
{
	struct wifi_ps_params params = { 0 };
	params.type = WIFI_PS_PARAM_STATE;
	params.enabled = enable;
	wifi_ps_set(iface, &params);
}

static struct net_mgmt_event_callback cb;
static struct net_mgmt_event_callback cb1;

K_EVENT_DEFINE(connect_event);
K_EVENT_DEFINE(net_event);

static void wifi_event_handler(struct net_mgmt_event_callback *cb,
			       uint64_t mgmt_event, struct net_if *iface)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;

	LOG_INF("Wi-Fi event - Layer: %llx Code: %llx Cmd: %llx Status: %d",
		NET_MGMT_GET_LAYER(mgmt_event),
		NET_MGMT_GET_LAYER_CODE(mgmt_event),
		NET_MGMT_GET_COMMAND(mgmt_event),
		status->status);

	if (mgmt_event == NET_EVENT_WIFI_CONNECT_RESULT) {
		if (status->status == 0) {
			LOG_INF("Connected to AP!");
			k_event_set(&connect_event, WIFI_EVENT_CONNECT_SUCCESS);
		} else {
			LOG_INF("Failed to connect to AP!");
			k_event_set(&connect_event, WIFI_EVENT_CONNECT_FAILED);
		}
	}
}

static void net_event_handler(struct net_mgmt_event_callback *cb,
			      uint64_t mgmt_event, struct net_if *iface)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;

	LOG_INF("NET event - Layer: %llx Code: %llx Cmd: %llx Status: %d",
		NET_MGMT_GET_LAYER(mgmt_event),
		NET_MGMT_GET_LAYER_CODE(mgmt_event),
		NET_MGMT_GET_COMMAND(mgmt_event),
		status->status);

	switch (mgmt_event) {
	case NET_EVENT_IPV4_ADDR_ADD:
		k_event_set(&net_event, EVENT_NET_IPV4_ADDR_ADD);
		LOG_INF("IPv4 address added");
		break;
	case NET_EVENT_IPV4_DHCP_BOUND:
		k_event_set(&net_event, EVENT_NET_IPV4_DHCP_BOUND);
		LOG_INF("DHCP bound - IP address assigned!");
		break;
	}
}
/*******************************************************************************
 * iConfig Connection Module (ported from http_connect_snippet.c)
 * 
 * Below are the socket helpers and FSM entry handlers used by
 * iConfig module to perform non-blocking HTTP/HTTPS downloads.
 ******************************************************************************/

static void http_request_socket_set_blocking(int socket_id, bool blocking)
{
	int flags = zsock_fcntl(socket_id, F_GETFL, 0);
	if (flags >= 0) {
		if (blocking) {
			zsock_fcntl(socket_id, F_SETFL, flags & ~O_NONBLOCK);
		} else {
			zsock_fcntl(socket_id, F_SETFL, flags | O_NONBLOCK);
		}
	}
}

static void http_request_set_port(struct sockaddr *endpoint, uint16_t port)
{
	if (endpoint->sa_family == AF_INET) {
		((struct sockaddr_in *)endpoint)->sin_port = htons(port);
	} else if (endpoint->sa_family == AF_INET6) {
		((struct sockaddr_in6 *)endpoint)->sin6_port = htons(port);
	}
}

static int http_request_socket_close(int socket)
{
	if ((socket >= 0) && zsock_close(socket)) {
		LOG_ERR("Socket close failed: %d (%s)", -errno, strerror(errno));
	}
	return -1;
}

static int http_request_socket_open(struct sockaddr endpoint, const char *hostname, size_t hostname_len,
				    const sec_tag_t *sec_tag_list, size_t sec_tag_count)
{
	int rc;
	int socket_id;

	if (!hostname || hostname_len == 0) {
		LOG_ERR("No hostname");
		return -EINVAL;
	}

	socket_id = zsock_socket(endpoint.sa_family, SOCK_STREAM, IPPROTO_TLS_1_2);
	if (socket_id < 0) {
		LOG_ERR("Failed to create socket: %d (%s)", -errno, strerror(errno));
		return -errno;
	}

	http_request_socket_set_blocking(socket_id, false);

	const int ciphersuites[] = {
		MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		MBEDTLS_TLS1_3_AES_128_GCM_SHA256,
		MBEDTLS_TLS1_3_AES_128_CCM_SHA256,
	};

	rc = zsock_setsockopt(socket_id, SOL_TLS, TLS_CIPHERSUITE_LIST,
			ciphersuites, sizeof(ciphersuites));
	if (rc < 0) {
		LOG_ERR("Failed to set ciphersuite list option (%d)", -errno);
		goto sock_fail;
	}

	if (sec_tag_list && sec_tag_count > 0) {
		rc = zsock_setsockopt(socket_id, SOL_TLS, TLS_SEC_TAG_LIST,
				sec_tag_list, sec_tag_count * sizeof(sec_tag_t));
		if (rc < 0) {
			LOG_ERR("Failed to set TLS_SEC_TAG_LIST: %d", -errno);
			goto sock_fail;
		}
	}

	rc = zsock_setsockopt(socket_id, SOL_TLS, TLS_HOSTNAME, hostname, hostname_len);
	if (rc < 0) {
		LOG_ERR("Failed to set TLS_HOSTNAME: %d", -errno);
		goto sock_fail;
	}

#if USE_TLS_VERIFY_NONE
	int enabled = TLS_PEER_VERIFY_NONE;
#else
	int enabled = TLS_PEER_VERIFY_REQUIRED;
#endif
	rc = zsock_setsockopt(socket_id, SOL_TLS, TLS_PEER_VERIFY, &enabled, sizeof(enabled));
	if (rc < 0) {
		LOG_ERR("Failed to set TLS_PEER_VERIFY: %d", -errno);
		goto sock_fail;
	}

	return socket_id;

sock_fail:
	zsock_close(socket_id);
	return -errno;
}

static int s_http_request_socket_connect_entry(void *self, struct fsm_msg_header *msg)
{
	struct http_request_ctx *ctx = (struct http_request_ctx *)self;

	LOG_DBG("%s Entry", __func__);

	if (!ctx->current_request) {
		LOG_ERR("No current request");
		fsm_node_send_message_id(MSG_ID_HTTP_REQUEST_ERROR, FSM_NODE_ID_HTTP_REQUEST);
		return 0;
	}

	ctx->connect_retries++;
	ctx->http_status_code = 0;

	http_request_set_port(&ctx->endpoint, ctx->current_request->port);

	ctx->socket = http_request_socket_close(ctx->socket);
	ctx->socket = http_request_socket_open(ctx->endpoint,
					       ctx->current_request->hostname,
					       strlen(ctx->current_request->hostname) + 1,
					       ctx->current_request->sec_tag_list,
					       ctx->current_request->sec_tag_count);

	if (ctx->socket < 0) {
		LOG_ERR("Failed to setup socket: %d (%s)", ctx->socket, strerror(-ctx->socket));
		fsm_node_send_message_id(MSG_ID_HTTP_REQUEST_ERROR, FSM_NODE_ID_HTTP_REQUEST);
		return 0;
	}

	LOG_INF("Connect to socket <%d> on endpoint <%s>", ctx->socket, ctx->current_request->hostname);
	socklen_t addrlen = (ctx->endpoint.sa_family == AF_INET6) ?
			    sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
	int rc = zsock_connect(ctx->socket, &ctx->endpoint, addrlen);
	if (rc < 0) {
		if (errno == EINPROGRESS) {
			LOG_INF("Connecting to socket: %d (EINPROGRESS) ...", ctx->socket);
			fsm_node_send_message_id(MSG_ID_HTTP_REQUEST_CONNECT_CHECK, FSM_NODE_ID_HTTP_REQUEST);
		} else {
			LOG_ERR("Connect failed: %d (%d: %s)", rc, errno, strerror(errno));
			fsm_node_send_message_id(MSG_ID_HTTP_REQUEST_ERROR, FSM_NODE_ID_HTTP_REQUEST);
		}
	} else {
		LOG_DBG("Connecting to socket: %d ...", ctx->socket);
		fsm_node_send_message_id(MSG_ID_HTTP_REQUEST_CONNECT_CHECK, FSM_NODE_ID_HTTP_REQUEST);
	}

	return 0;
}

static int s_http_request_socket_connection_check_entry(void *self, struct fsm_msg_header *msg)
{
	struct http_request_ctx *ctx = (struct http_request_ctx *)self;

	LOG_DBG("%s Entry", __func__);

	if (!ctx->current_request) {
		LOG_ERR("No current request");
		return -EFAULT;
	}

	struct zsock_pollfd pfd = {
		.fd = ctx->socket,
		.events = ZSOCK_POLLOUT,
	};

	ctx->connect_retries++;

	int rc = zsock_poll(&pfd, 1, 0);
	if (rc > 0 && (pfd.revents & ZSOCK_POLLOUT)) {
		int error = 0;
		socklen_t len = sizeof(error);

		rc = zsock_getsockopt(ctx->socket, SOL_SOCKET, SO_ERROR, &error, &len);
		if (rc == 0 && error == 0) {
			LOG_INF("Socket (%d) connected", ctx->socket);
			fsm_node_send_message_id(MSG_ID_HTTP_REQUEST_CONNECTED, FSM_NODE_ID_HTTP_REQUEST);
			return 0;
		} else {
			LOG_WRN("Socket error: %d (SO_ERROR: %d)", rc, error);
		}
	}

	return 0;
}

static const sec_tag_t iconfig_sec_tag_list[] = {
	TLS_TAG_HTTPS_CA_CERTIFICATE,
	CLIENT_CERT_TAG,
};

static int https_client_connect_and_request(struct net_if *iface, const char *method, const char *path, const char *body)
{
	struct http_request_info req_info = {
		.hostname = HTTPS_SERVER,
		.port = HTTPS_PORT,
		.sec_tag_list = iconfig_sec_tag_list,
		.sec_tag_count = ARRAY_SIZE(iconfig_sec_tag_list),
	};

	struct http_request_ctx ctx = {
		.socket = -1,
		.current_request = &req_info,
		.connect_retries = 0,
		.http_status_code = 0,
	};

	memset(&ctx.endpoint, 0, sizeof(ctx.endpoint));
	ctx.endpoint.sa_family = AF_INET;
	struct sockaddr_in *sin = (struct sockaddr_in *)&ctx.endpoint;
#if USE_HTTPS_SERVER_IP
	zsock_inet_pton(AF_INET, HTTPS_SERVER_IP, &sin->sin_addr);
#else
	struct zsock_addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
	};
	struct zsock_addrinfo *res = NULL;
	int ret = zsock_getaddrinfo(HTTPS_SERVER, NULL, &hints, &res);
	if (ret < 0) {
		LOG_ERR("DNS resolution failed: %d", ret);
		return -EHOSTUNREACH;
	}
	memcpy(&sin->sin_addr, &((struct sockaddr_in *)res->ai_addr)->sin_addr, sizeof(struct in_addr));
	zsock_freeaddrinfo(res);
#endif

	last_fsm_msg_id = -1;

	LOG_INF("Triggering connect entry...");
	s_http_request_socket_connect_entry(&ctx, NULL);

	if (last_fsm_msg_id == MSG_ID_HTTP_REQUEST_ERROR) {
		LOG_ERR("Connect entry returned error");
		return -EIO;
	}
	LOG_INF("Polling for connection check...");
	int timeout_ms = 10000;
	int elapsed_ms = 0;
	while (last_fsm_msg_id != MSG_ID_HTTP_REQUEST_CONNECTED && elapsed_ms < timeout_ms) {
		s_http_request_socket_connection_check_entry(&ctx, NULL);
		k_msleep(100);
		elapsed_ms += 100;
	}

	if (last_fsm_msg_id != MSG_ID_HTTP_REQUEST_CONNECTED) {
		LOG_ERR("Connection check timed out or failed!");
		http_request_socket_close(ctx.socket);
		return -ETIMEDOUT;
	}

	LOG_INF("SUCCESS: Connection state machine connected successfully!");

	/* 3. Send HTTP request and verify data exchange */
	static char request_buffer[HTTP_MAX_BUFFER_SIZE];
	static char response_buffer[HTTP_MAX_BUFFER_SIZE];

	if (strcmp(method, "PUT") == 0) {
		snprintf(request_buffer, sizeof(request_buffer),
			 "PUT %s HTTP/1.1\r\n"
			 "Host: %s\r\n"
			 "Connection: close\r\n"
			 "Content-Type: text/plain\r\n"
			 "Content-Length: %d\r\n"
			 "User-Agent: Zephyr-HTTPS-Client/1.0\r\n"
			 "\r\n"
			 "%s",
			 path, HTTPS_SERVER, body ? (int)strlen(body) : 0, body ? body : "");
	} else {
		snprintf(request_buffer, sizeof(request_buffer),
			 "GET %s HTTP/1.1\r\n"
			 "Host: %s\r\n"
			 "Connection: close\r\n"
			 "User-Agent: Zephyr-HTTPS-Client/1.0\r\n"
			 "\r\n",
			 path, HTTPS_SERVER);
	}

	int bytes_sent = zsock_send(ctx.socket, request_buffer, strlen(request_buffer), 0);
	if (bytes_sent < 0) {
		LOG_ERR("Send failed: %d", errno);
		http_request_socket_close(ctx.socket);
		return -errno;
	}

	LOG_INF("HTTP request sent (%d bytes)", bytes_sent);

	/* Poll for incoming response */
	struct zsock_pollfd r_pfd = {
		.fd = ctx.socket,
		.events = ZSOCK_POLLIN | ZSOCK_POLLERR | ZSOCK_POLLHUP,
		.revents = 0,
	};
	int poll_ret = zsock_poll(&r_pfd, 1, 10000);
	if (poll_ret < 0) {
		LOG_ERR("Response poll failed: errno=%d (%s)", errno, strerror(errno));
		http_request_socket_close(ctx.socket);
		return -errno;
	}
	if (poll_ret == 0) {
		LOG_ERR("Timed out waiting for HTTPS response");
		http_request_socket_close(ctx.socket);
		return -ETIMEDOUT;
	}
	if (r_pfd.revents & (ZSOCK_POLLERR | ZSOCK_POLLHUP | ZSOCK_POLLNVAL)) {
		LOG_ERR("Response socket event error: revents=0x%x", r_pfd.revents);
		http_request_socket_close(ctx.socket);
		return -ECONNRESET;
	}
	if (r_pfd.revents & ZSOCK_POLLIN) {
		int bytes_recv = zsock_recv(ctx.socket, response_buffer, sizeof(response_buffer) - 1, 0);
		if (bytes_recv > 0) {
			response_buffer[bytes_recv] = '\0';
			LOG_INF("Response received:\n%s", response_buffer);
		} else if (bytes_recv == 0) {
			LOG_WRN("Server closed connection without a response");
		} else {
			LOG_ERR("Recv failed: errno=%d (%s)", errno, strerror(errno));
			http_request_socket_close(ctx.socket);
			return -errno;
		}
	}

	http_request_socket_close(ctx.socket);
	return 0;
}

int main(void)
{
	int ret = 0;
	struct net_if *iface;
	struct wifi_connect_req_params config = {0};
	uint32_t events;

	LOG_INF("Starting HTTPS client application...");
	k_msleep(3000);
	iface = net_if_get_wifi_sta();
	if (iface == NULL) {
		LOG_ERR("Cannot find the Wi-Fi interface");
		return 0;
	}

	net_if_up(iface);

	net_mgmt_init_event_callback(&cb, wifi_event_handler,
				     NET_EVENT_WIFI_CONNECT_RESULT);
	net_mgmt_add_event_callback(&cb);

	net_mgmt_init_event_callback(&cb1, net_event_handler,
				     NET_EVENT_IPV4_ADDR_ADD | NET_EVENT_IPV4_DHCP_BOUND);
	net_mgmt_add_event_callback(&cb1);

	/* Prepare connection config */
	config.ssid = (const uint8_t *)WIFI_SSID;
	config.ssid_length = strlen(WIFI_SSID);
	config.psk = (const uint8_t *)WIFI_PSK;
	config.psk_length = strlen(WIFI_PSK);
	config.security = WIFI_SECURITY_TYPE_PSK;
	config.channel = WIFI_CHANNEL_ANY;
	config.band = WIFI_FREQ_BAND_2_4_GHZ;

	LOG_INF("Waiting 3 seconds before Wi-Fi connect request...");
	k_sleep(K_SECONDS(3));

	do {
		LOG_INF("Connecting to network (SSID: %s)...", WIFI_SSID);
		if (net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &config,
			     sizeof(struct wifi_connect_req_params))) {
			LOG_ERR("Wi-Fi connect request failed");
			return 0;
		}

		/* Wait for connection result */
		events = k_event_wait(&connect_event, WIFI_EVENT_ALL, true, K_FOREVER);
		if (events == WIFI_EVENT_CONNECT_SUCCESS) {
			LOG_INF("Joined network!");
			break;
		}
	} while (1);

	/* Wait for DHCP lease */
	do {
		events = k_event_wait(&net_event, NET_EVENT_ALL, true, K_FOREVER);
		if (events & EVENT_NET_IPV4_DHCP_BOUND) {
			LOG_INF("DHCP lease fully bound!");
			break;
		}
	} while (1);

	/* Allow background driver thread time to reconfigure DNS servers */
	LOG_INF("Waiting 500ms for DNS server configuration...");
	k_msleep(500);

#if ENABLE_WIFI_DPM
	LOG_INF("Enabling Wi-Fi DPM/PS for sleep testing...");
	wifi_ps_state_set(iface, true);
#else
	LOG_INF("Disabling Wi-Fi DPM/PS...");
	wifi_ps_state_set(iface, false);
#endif

//	LOG_INF("Waiting 2 seconds before starting HTTPS client...");
//	k_sleep(K_SECONDS(2));

	setup_credentials();
	LOG_INF("Credentials setup completed");

	LOG_INF("Starting HTTPS client application...");
	LOG_INF("=== RUNNING HTTPS GET REQUEST ===");
	ret = https_client_connect_and_request(iface, "GET", "/", NULL);
	if (ret < 0) {
		LOG_ERR("HTTPS GET failed: %d", ret);
	}

	LOG_INF("Waiting 2 seconds before running PUT request...");
	k_sleep(K_SECONDS(2));

	LOG_INF("=== RUNNING HTTPS PUT REQUEST ===");
	ret = https_client_connect_and_request(iface, "PUT", "/put", "Hello World!");
	if (ret < 0) {
		LOG_ERR("HTTPS PUT failed: %d", ret);
		return ret;
	}

	LOG_INF("Application finished");
	return 0;
}
