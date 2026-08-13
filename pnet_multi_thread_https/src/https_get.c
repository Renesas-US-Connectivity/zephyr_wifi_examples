/*
 * Phase 4 HTTPS GET — LAN provision server returns MQTT endpoint + PEM certs.
 *
 * Target: 192.168.50.243:4443 (same machine as MQTT broker).
 * Trust: TLS_PEER_VERIFY_NONE for bring-up (self-signed test server).
 *
 * JSON fields: mqtt_host, mqtt_port, mqtt_client_id,
 *              mqtt_ca_pem, mqtt_client_cert_pem, mqtt_private_key_pem
 * (PEM strings use \\n escapes). Falls back to ca_cert.h if certs absent.
 *
 * Always close the TLS socket and release any HTTPS credentials before
 * return so MQTT (sec tag 42) still has heap/credential room.
 */

#include "https_get.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/posix/fcntl.h>
#include <mbedtls/ssl_ciphersuites.h>

/* Phase 2: LAN HTTPS on the MQTT broker machine */
#define HTTPS_SERVER         "192.168.50.243"
#define HTTPS_PORT           4443
#define HTTPS_PATH           "/"

#define USE_HTTPS_SERVER_IP  1
#define HTTPS_SERVER_IP      "192.168.50.243"

/* Self-signed test server — verify off for Phase 2 bring-up */
#define USE_TLS_VERIFY_NONE  1

/* Headers + JSON with three PEMs (~6–7 KiB); keep headroom. */
#define HTTP_MAX_BUFFER_SIZE 12288
/* Keep HTTPS tags clear of MQTT sec tag (42) in pnet_multi_threaded.c */
#define TLS_TAG_HTTPS_CA_CERTIFICATE 1
#define HTTPS_CLIENT_CERT_TAG        2

enum fsm_msg_id {
	MSG_ID_HTTP_REQUEST_ERROR,
	MSG_ID_HTTP_REQUEST_CONNECT_CHECK,
	MSG_ID_HTTP_REQUEST_CONNECTED,
};

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
};

static int last_fsm_msg_id = -1;

static void fsm_node_send_message_id(int msg_id)
{
	last_fsm_msg_id = msg_id;
}

/* Same PEMs as Test_TLS_https_client/src/main.c */
static const uint8_t ca_certificate[] =
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

static const uint8_t device_certificate[] =
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

static const uint8_t device_key[] =
"-----BEGIN EC PRIVATE KEY-----\n"
"MHcCAQEEIKooI0AOnF/8L57NdmXDD5vtC2/ol3N73LDCgRZ7uUjnoAoGCCqGSM49\n"
"AwEHoUQDQgAEORBMRf9qyEFyU9XqJXqdUjKGk74YePP9y6pgmKsfJuzsVg4o6LGO\n"
"zYBGEUiCZQwa3xIeseCenm6zwmrYV57AMw==\n"
"-----END EC PRIVATE KEY-----\n";

static int setup_https_credentials(void)
{
	int ret;

	/* Clear any leftover HTTPS tags from a previous attempt. */
	(void)tls_credential_delete(TLS_TAG_HTTPS_CA_CERTIFICATE,
				     TLS_CREDENTIAL_CA_CERTIFICATE);
	(void)tls_credential_delete(HTTPS_CLIENT_CERT_TAG,
				     TLS_CREDENTIAL_SERVER_CERTIFICATE);
	(void)tls_credential_delete(HTTPS_CLIENT_CERT_TAG,
				     TLS_CREDENTIAL_PRIVATE_KEY);

	ret = tls_credential_add(TLS_TAG_HTTPS_CA_CERTIFICATE,
				 TLS_CREDENTIAL_CA_CERTIFICATE,
				 ca_certificate, sizeof(ca_certificate));
	if (ret < 0 && ret != -EEXIST) {
		printk("[HTTPS] Failed to add CA certificate: %d\n", ret);
		return ret;
	}

	ret = tls_credential_add(HTTPS_CLIENT_CERT_TAG,
				 TLS_CREDENTIAL_SERVER_CERTIFICATE,
				 device_certificate, sizeof(device_certificate));
	if (ret < 0 && ret != -EEXIST) {
		printk("[HTTPS] Failed to register client certificate: %d\n", ret);
		return ret;
	}

	ret = tls_credential_add(HTTPS_CLIENT_CERT_TAG,
				 TLS_CREDENTIAL_PRIVATE_KEY,
				 device_key, sizeof(device_key));
	if (ret < 0 && ret != -EEXIST) {
		printk("[HTTPS] Failed to register client private key: %d\n", ret);
		return ret;
	}

	return 0;
}

/* Free HTTPS credential slots so MQTT can allocate its own (tag 42). */
static void teardown_https_credentials(void)
{
	(void)tls_credential_delete(TLS_TAG_HTTPS_CA_CERTIFICATE,
				     TLS_CREDENTIAL_CA_CERTIFICATE);
	(void)tls_credential_delete(HTTPS_CLIENT_CERT_TAG,
				     TLS_CREDENTIAL_SERVER_CERTIFICATE);
	(void)tls_credential_delete(HTTPS_CLIENT_CERT_TAG,
				     TLS_CREDENTIAL_PRIVATE_KEY);
	printk("[HTTPS] Credentials released for MQTT\n");
}

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
	if (socket >= 0) {
		if (zsock_close(socket)) {
			printk("[HTTPS] Socket close failed: %d (%s)\n",
			       -errno, strerror(errno));
		}
	}
	return -1;
}

static int http_request_socket_open(struct sockaddr endpoint, const char *hostname,
				    size_t hostname_len, const sec_tag_t *sec_tag_list,
				    size_t sec_tag_count)
{
	int rc;
	int socket_id;

	if (!hostname || hostname_len == 0) {
		printk("[HTTPS] No hostname\n");
		return -EINVAL;
	}

	socket_id = zsock_socket(endpoint.sa_family, SOCK_STREAM, IPPROTO_TLS_1_2);
	if (socket_id < 0) {
		printk("[HTTPS] Failed to create socket: %d (%s)\n", -errno, strerror(errno));
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
		printk("[HTTPS] Failed to set ciphersuite list (%d)\n", -errno);
		goto sock_fail;
	}

	if (sec_tag_list && sec_tag_count > 0) {
		rc = zsock_setsockopt(socket_id, SOL_TLS, TLS_SEC_TAG_LIST,
				      sec_tag_list, sec_tag_count * sizeof(sec_tag_t));
		if (rc < 0) {
			printk("[HTTPS] Failed to set TLS_SEC_TAG_LIST: %d\n", -errno);
			goto sock_fail;
		}
	}

	rc = zsock_setsockopt(socket_id, SOL_TLS, TLS_HOSTNAME, hostname, hostname_len);
	if (rc < 0) {
		printk("[HTTPS] Failed to set TLS_HOSTNAME: %d\n", -errno);
		goto sock_fail;
	}

#if USE_TLS_VERIFY_NONE
	int enabled = TLS_PEER_VERIFY_NONE;
#else
	int enabled = TLS_PEER_VERIFY_REQUIRED;
#endif
	rc = zsock_setsockopt(socket_id, SOL_TLS, TLS_PEER_VERIFY, &enabled, sizeof(enabled));
	if (rc < 0) {
		printk("[HTTPS] Failed to set TLS_PEER_VERIFY: %d\n", -errno);
		goto sock_fail;
	}

	return socket_id;

sock_fail:
	zsock_close(socket_id);
	return -errno;
}

static int s_http_request_socket_connect_entry(struct http_request_ctx *ctx)
{
	if (!ctx->current_request) {
		printk("[HTTPS] No current request\n");
		fsm_node_send_message_id(MSG_ID_HTTP_REQUEST_ERROR);
		return 0;
	}

	ctx->connect_retries++;
	http_request_set_port(&ctx->endpoint, ctx->current_request->port);

	ctx->socket = http_request_socket_close(ctx->socket);
	ctx->socket = http_request_socket_open(ctx->endpoint,
					       ctx->current_request->hostname,
					       strlen(ctx->current_request->hostname) + 1,
					       ctx->current_request->sec_tag_list,
					       ctx->current_request->sec_tag_count);

	if (ctx->socket < 0) {
		printk("[HTTPS] Failed to setup socket: %d\n", ctx->socket);
		fsm_node_send_message_id(MSG_ID_HTTP_REQUEST_ERROR);
		return 0;
	}

	printk("[HTTPS] Connect to socket <%d> on endpoint <%s>\n",
	       ctx->socket, ctx->current_request->hostname);

	socklen_t addrlen = (ctx->endpoint.sa_family == AF_INET6) ?
			    sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
	int rc = zsock_connect(ctx->socket, &ctx->endpoint, addrlen);

	if (rc < 0) {
		if (errno == EINPROGRESS) {
			printk("[HTTPS] Connecting (EINPROGRESS)...\n");
			fsm_node_send_message_id(MSG_ID_HTTP_REQUEST_CONNECT_CHECK);
		} else {
			printk("[HTTPS] Connect failed: %d (%s)\n", errno, strerror(errno));
			fsm_node_send_message_id(MSG_ID_HTTP_REQUEST_ERROR);
		}
	} else {
		fsm_node_send_message_id(MSG_ID_HTTP_REQUEST_CONNECT_CHECK);
	}

	return 0;
}

static int s_http_request_socket_connection_check_entry(struct http_request_ctx *ctx)
{
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
			printk("[HTTPS] Socket (%d) connected\n", ctx->socket);
			fsm_node_send_message_id(MSG_ID_HTTP_REQUEST_CONNECTED);
			return 0;
		}
		printk("[HTTPS] Socket error: %d (SO_ERROR: %d)\n", rc, error);
		fsm_node_send_message_id(MSG_ID_HTTP_REQUEST_ERROR);
	}

	return 0;
}

static const sec_tag_t https_sec_tag_list[] = {
	TLS_TAG_HTTPS_CA_CERTIFICATE,
	HTTPS_CLIENT_CERT_TAG,
};

/*
 * Expected JSON (Phase 4):
 * {"mqtt_host":"...","mqtt_port":8883,"mqtt_client_id":"...",
 *  "mqtt_ca_pem":"-----BEGIN CERTIFICATE-----\\n...\\n-----END...\\n",
 *  "mqtt_client_cert_pem":"...",
 *  "mqtt_private_key_pem":"..."}
 */
static bool json_find_string_value(const char *json, const char *key,
				   const char **val_start, const char **val_end)
{
	char needle[48];
	const char *p;
	const char *end;

	if (json == NULL || key == NULL || val_start == NULL || val_end == NULL) {
		return false;
	}

	snprintk(needle, sizeof(needle), "\"%s\"", key);
	p = strstr(json, needle);
	if (p == NULL) {
		return false;
	}
	p = strchr(p + strlen(needle), ':');
	if (p == NULL) {
		return false;
	}
	p++;
	while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
		p++;
	}
	if (*p != '"') {
		return false;
	}
	p++;
	end = p;
	while (*end != '\0') {
		if (*end == '\\' && end[1] != '\0') {
			end += 2;
			continue;
		}
		if (*end == '"') {
			*val_start = p;
			*val_end = end;
			return true;
		}
		end++;
	}
	return false;
}

/* Copy JSON string value and unescape \\n \\r \\t \\\" \\\\ */
static bool json_copy_string_field(const char *json, const char *key,
				   char *out, size_t out_len)
{
	const char *p;
	const char *end;
	size_t o = 0;

	if (out == NULL || out_len == 0U) {
		return false;
	}
	if (!json_find_string_value(json, key, &p, &end)) {
		return false;
	}

	while (p < end) {
		char c;

		if (*p == '\\' && (p + 1) < end) {
			p++;
			switch (*p) {
			case 'n':
				c = '\n';
				break;
			case 'r':
				c = '\r';
				break;
			case 't':
				c = '\t';
				break;
			case '"':
			case '\\':
			case '/':
				c = *p;
				break;
			default:
				c = *p;
				break;
			}
			p++;
		} else {
			c = *p++;
		}
		if (o + 1U >= out_len) {
			return false;
		}
		out[o++] = c;
	}
	out[o] = '\0';
	return o > 0U;
}

static bool json_copy_u16_field(const char *json, const char *key, uint16_t *out)
{
	char needle[48];
	const char *p;
	unsigned long v;
	char *endptr;

	if (json == NULL || key == NULL || out == NULL) {
		return false;
	}

	snprintk(needle, sizeof(needle), "\"%s\"", key);
	p = strstr(json, needle);
	if (p == NULL) {
		return false;
	}
	p = strchr(p + strlen(needle), ':');
	if (p == NULL) {
		return false;
	}
	p++;
	while (*p == ' ' || *p == '\t') {
		p++;
	}
	v = strtoul(p, &endptr, 10);
	if (endptr == p || v == 0UL || v > 65535UL) {
		return false;
	}
	*out = (uint16_t)v;
	return true;
}

static const char *http_body_start(const char *resp)
{
	const char *p;

	if (resp == NULL) {
		return NULL;
	}
	p = strstr(resp, "\r\n\r\n");
	if (p != NULL) {
		return p + 4;
	}
	p = strstr(resp, "\n\n");
	if (p != NULL) {
		return p + 2;
	}
	return NULL;
}

static bool parse_mqtt_cfg_from_http(const char *resp, struct https_mqtt_cfg *cfg)
{
	const char *body;

	if (cfg == NULL) {
		return false;
	}

	memset(cfg, 0, sizeof(*cfg));
	body = http_body_start(resp);
	if (body == NULL || *body == '\0') {
		printk("[HTTPS] No HTTP body to parse\n");
		return false;
	}

	printk("[HTTPS] Body len=%u (certs not logged)\n", (unsigned)strlen(body));

	if (!json_copy_string_field(body, "mqtt_host", cfg->host, sizeof(cfg->host))) {
		printk("[HTTPS] Missing mqtt_host\n");
		return false;
	}
	if (!json_copy_u16_field(body, "mqtt_port", &cfg->port)) {
		printk("[HTTPS] Missing mqtt_port\n");
		return false;
	}
	if (!json_copy_string_field(body, "mqtt_client_id", cfg->client_id,
				    sizeof(cfg->client_id))) {
		printk("[HTTPS] Missing mqtt_client_id\n");
		return false;
	}

	cfg->valid = true;
	printk("[HTTPS] Parsed MQTT cfg: %s:%u id=%s\n",
	       cfg->host, cfg->port, cfg->client_id);

	/* Phase 4 PEMs — optional; MQTT falls back to ca_cert.h if missing. */
	if (json_copy_string_field(body, "mqtt_ca_pem", cfg->ca_pem,
				   sizeof(cfg->ca_pem)) &&
	    json_copy_string_field(body, "mqtt_client_cert_pem",
				   cfg->client_cert_pem,
				   sizeof(cfg->client_cert_pem)) &&
	    json_copy_string_field(body, "mqtt_private_key_pem",
				   cfg->private_key_pem,
				   sizeof(cfg->private_key_pem))) {
		cfg->ca_pem_len = strlen(cfg->ca_pem);
		cfg->client_cert_pem_len = strlen(cfg->client_cert_pem);
		cfg->private_key_pem_len = strlen(cfg->private_key_pem);
		/* tls_credential_add expects length including NUL for PEM text. */
		cfg->ca_pem_len++;
		cfg->client_cert_pem_len++;
		cfg->private_key_pem_len++;
		cfg->certs_valid = true;
		printk("[HTTPS] Parsed MQTT PEMs: ca=%u client=%u key=%u\n",
		       (unsigned)cfg->ca_pem_len,
		       (unsigned)cfg->client_cert_pem_len,
		       (unsigned)cfg->private_key_pem_len);
	} else {
		printk("[HTTPS] MQTT PEMs missing — will use flash defaults\n");
	}

	return true;
}

int https_phase1_get(struct https_mqtt_cfg *cfg)
{
	static char request_buffer[512];
	static char response_buffer[HTTP_MAX_BUFFER_SIZE];
	struct http_request_ctx ctx = {
		.socket = -1,
		.connect_retries = 0,
	};
	int ret = 0;
	bool creds_loaded = false;
	int total_recv = 0;

	if (cfg != NULL) {
		memset(cfg, 0, sizeof(*cfg));
	}

	printk("[HTTPS] Phase 4 GET %s:%d%s (verify=%s)\n",
	       HTTPS_SERVER, HTTPS_PORT, HTTPS_PATH,
	       USE_TLS_VERIFY_NONE ? "none" : "required");

#if !USE_TLS_VERIFY_NONE
	ret = setup_https_credentials();
	if (ret < 0) {
		goto out;
	}
	creds_loaded = true;

	struct http_request_info req_info = {
		.hostname = HTTPS_SERVER,
		.port = HTTPS_PORT,
		.sec_tag_list = https_sec_tag_list,
		.sec_tag_count = ARRAY_SIZE(https_sec_tag_list),
	};
#else
	/* Bring-up: no CA/client certs; peer verify disabled. */
	struct http_request_info req_info = {
		.hostname = HTTPS_SERVER,
		.port = HTTPS_PORT,
		.sec_tag_list = NULL,
		.sec_tag_count = 0,
	};
#endif

	ctx.current_request = &req_info;
	memset(&ctx.endpoint, 0, sizeof(ctx.endpoint));
	ctx.endpoint.sa_family = AF_INET;
	struct sockaddr_in *sin = (struct sockaddr_in *)&ctx.endpoint;

#if USE_HTTPS_SERVER_IP
	if (zsock_inet_pton(AF_INET, HTTPS_SERVER_IP, &sin->sin_addr) != 1) {
		printk("[HTTPS] Invalid server IP: %s\n", HTTPS_SERVER_IP);
		ret = -EINVAL;
		goto out;
	}
	printk("[HTTPS] Using literal IP %s (DNS skipped)\n", HTTPS_SERVER_IP);
#else
	struct zsock_addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
	};
	struct zsock_addrinfo *res = NULL;

	ret = zsock_getaddrinfo(HTTPS_SERVER, NULL, &hints, &res);
	if (ret < 0 || res == NULL) {
		printk("[HTTPS] DNS resolution failed: %d\n", ret);
		ret = -EHOSTUNREACH;
		goto out;
	}
	memcpy(&sin->sin_addr, &((struct sockaddr_in *)res->ai_addr)->sin_addr,
	       sizeof(struct in_addr));
	zsock_freeaddrinfo(res);
#endif

	last_fsm_msg_id = -1;
	s_http_request_socket_connect_entry(&ctx);

	if (last_fsm_msg_id == MSG_ID_HTTP_REQUEST_ERROR) {
		printk("[HTTPS] Connect entry returned error\n");
		ret = -EIO;
		goto out;
	}

	int timeout_ms = 10000;
	int elapsed_ms = 0;

	while (last_fsm_msg_id != MSG_ID_HTTP_REQUEST_CONNECTED &&
	       last_fsm_msg_id != MSG_ID_HTTP_REQUEST_ERROR &&
	       elapsed_ms < timeout_ms) {
		s_http_request_socket_connection_check_entry(&ctx);
		k_msleep(100);
		elapsed_ms += 100;
	}

	if (last_fsm_msg_id == MSG_ID_HTTP_REQUEST_ERROR) {
		printk("[HTTPS] Connection check reported error\n");
		ret = -ECONNABORTED;
		goto out;
	}

	if (last_fsm_msg_id != MSG_ID_HTTP_REQUEST_CONNECTED) {
		printk("[HTTPS] Connection check timed out or failed\n");
		ret = -ETIMEDOUT;
		goto out;
	}

	printk("[HTTPS] TLS connected — sending GET\n");

	snprintk(request_buffer, sizeof(request_buffer),
		 "GET %s HTTP/1.1\r\n"
		 "Host: %s\r\n"
		 "Connection: close\r\n"
		 "User-Agent: Zephyr-HTTPS-Client/1.0\r\n"
		 "\r\n",
		 HTTPS_PATH, HTTPS_SERVER);

	int bytes_sent = zsock_send(ctx.socket, request_buffer, strlen(request_buffer), 0);

	if (bytes_sent < 0) {
		printk("[HTTPS] Send failed: %d\n", errno);
		ret = -errno;
		goto out;
	}
	printk("[HTTPS] HTTP request sent (%d bytes)\n", bytes_sent);

	/* Drain until peer closes or buffer is full (need full body for parse). */
	total_recv = 0;
	while (total_recv < (int)sizeof(response_buffer) - 1) {
		struct zsock_pollfd r_pfd = {
			.fd = ctx.socket,
			.events = ZSOCK_POLLIN | ZSOCK_POLLERR | ZSOCK_POLLHUP,
			.revents = 0,
		};
		int poll_ret = zsock_poll(&r_pfd, 1, 5000);

		if (poll_ret < 0) {
			printk("[HTTPS] Response poll failed: errno=%d\n", errno);
			ret = -errno;
			goto out;
		}
		if (poll_ret == 0) {
			if (total_recv > 0) {
				break;
			}
			printk("[HTTPS] Timed out waiting for response\n");
			ret = -ETIMEDOUT;
			goto out;
		}
		if (r_pfd.revents & (ZSOCK_POLLERR | ZSOCK_POLLNVAL)) {
			printk("[HTTPS] Response socket event error: revents=0x%x\n",
			       r_pfd.revents);
			ret = -ECONNRESET;
			goto out;
		}

		if (r_pfd.revents & ZSOCK_POLLIN) {
			int bytes_recv = zsock_recv(ctx.socket,
						    response_buffer + total_recv,
						    sizeof(response_buffer) - 1 - total_recv,
						    0);

			if (bytes_recv > 0) {
				total_recv += bytes_recv;
				continue;
			}
			if (bytes_recv == 0) {
				break;
			}
			printk("[HTTPS] Recv failed: errno=%d\n", errno);
			ret = -errno;
			goto out;
		}

		if (r_pfd.revents & ZSOCK_POLLHUP) {
			break;
		}
	}

	if (total_recv <= 0) {
		printk("[HTTPS] Server closed connection without a response\n");
		ret = -ENOTCONN;
		goto out;
	}

	response_buffer[total_recv] = '\0';
	printk("[HTTPS] Response received (%d bytes):\n%s\n",
	       total_recv, response_buffer);

	if (cfg != NULL) {
		if (!parse_mqtt_cfg_from_http(response_buffer, cfg)) {
			printk("[HTTPS] MQTT cfg parse failed (MQTT will use defaults)\n");
		}
	}

	ret = 0;
	printk("[HTTPS] Phase 4 GET completed successfully\n");

out:
	ctx.socket = http_request_socket_close(ctx.socket);

	if (creds_loaded) {
		teardown_https_credentials();
	}

	k_msleep(200);

	return ret;
}
