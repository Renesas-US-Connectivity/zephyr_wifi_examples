/*
 * Customer-like HTTPS flow built on Zephyr's native http_client.
 *
 * The current defaults still target the local test server, but the request
 * pattern now matches the customer logs more closely:
 * 1. HTTPS GET bootstrap
 * 2. HTTPS POST onboarding probe
 *
 * To mirror the customer cloud directly, switch these to hostnames like:
 *   pinnediconfig.aaecosystem.com:443 /devices/J3APC0006A
 *   enroll.eu-west-1.iot2.dev.aaecosystem.com:443 /onboard
 */

#include "https_get.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/net/http/client.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/posix/fcntl.h>
#include <zephyr/net/dns_resolve.h>
#include <zephyr/net/socket_service.h>
#include <zephyr/random/random.h>

#include <mbedtls/ssl_ciphersuites.h>

/*
 * CUSTOMER_REPRO = 1 makes the HTTPS path behave like the customer
 * application (gorm http_request on Zephyr http_client + socket service):
 *
 *  - WAN HTTPS servers with real RTT (150-400 ms) and real certificate
 *    chains. A LAN self-signed server answers in < 5 ms, which hides the
 *    TCP-connect / TLS-handshake timing races seen in the customer logs.
 *  - Asynchronous DNS (dns_get_addr_info + callback) started right at
 *    DHCP_BOUND, with 1.0-1.9 s random backoff between attempts.
 *  - Non-blocking TLS connect; completion is waited through the Zephyr
 *    socket service thread (subsys/net/lib/sockets/sockets_service.c),
 *    i.e. poll() runs in a different thread than connect()/send().
 *  - Per request: up to 2 connect attempts, each on a brand-new socket
 *    created immediately after close (same remote fd re-used by RA6W1),
 *    then a request backoff and fresh DNS - like "Iconfig backoff".
 *  - TLS peer verify OPTIONAL: the full server chain is parsed and
 *    verified (CPU time / idle gaps like the customer) without needing
 *    the CA, and without aborting on verification failure.
 *
 * Set CUSTOMER_REPRO to 0 to go back to the original LAN test server flow.
 */
#define CUSTOMER_REPRO            1

#if CUSTOMER_REPRO
/*
 * Neutral public endpoints on the same infrastructure as the customer:
 *   customer GET  pinnediconfig.aaecosystem.com            -> Cloudflare
 *   customer POST enroll.eu-west-1.iot2.dev.aaecosystem.com -> AWS
 * To use the exact customer hosts (only with the customer's permission):
 *   "pinnediconfig.aaecosystem.com", "/devices/J3APC0006A"
 *   "enroll.eu-west-1.iot2.dev.aaecosystem.com", "/onboard"
 */
#define HTTPS_BOOTSTRAP_SERVER    "www.cloudflare.com"
#define HTTPS_BOOTSTRAP_PORT      443
#define HTTPS_BOOTSTRAP_PATH      "/cdn-cgi/trace"

#define HTTPS_ONBOARD_SERVER      "httpbin.org"
#define HTTPS_ONBOARD_PORT        443
#define HTTPS_ONBOARD_PATH        "/post"

#define HTTPS_PEER_VERIFY_MODE    TLS_PEER_VERIFY_OPTIONAL
#else
#define HTTPS_BOOTSTRAP_SERVER    "172.20.10.2"
#define HTTPS_BOOTSTRAP_PORT      4443
#define HTTPS_BOOTSTRAP_PATH      "/"

#define HTTPS_ONBOARD_SERVER      HTTPS_BOOTSTRAP_SERVER
#define HTTPS_ONBOARD_PORT        HTTPS_BOOTSTRAP_PORT
#define HTTPS_ONBOARD_PATH        "/onboard"

#define HTTPS_PEER_VERIFY_MODE    TLS_PEER_VERIFY_NONE
#endif

/* No credential store use for HTTPS (customer failure is before verify). */
#define USE_TLS_VERIFY_NONE       1

/* Customer-like retry policy */
#define HTTPS_CONNECT_ATTEMPTS    2
#define HTTPS_REQUEST_CYCLES      6
#define HTTPS_DNS_TIMEOUT_MS      5000
#define HTTPS_BACKOFF_MIN_MS      1000
#define HTTPS_BACKOFF_JITTER_MS   900

#define HTTP_MAX_BODY_SIZE        12288
#define HTTP_RECV_CHUNK_SIZE      2048
#define HTTPS_CONNECT_TIMEOUT_MS  15000
#define HTTPS_REQUEST_TIMEOUT_MS  15000
#define HTTPS_ONBOARD_CSR_FILL    896

/* Keep HTTPS tags clear of MQTT sec tag (42) in pnet_multi_threaded.c */
#define TLS_TAG_HTTPS_CA_CERTIFICATE 1
#define HTTPS_CLIENT_CERT_TAG        2

struct https_request_desc {
	const char *label;
	const char *hostname;
	uint16_t port;
	const char *path;
	enum http_method method;
	const char *payload;
	const char *content_type;
	const sec_tag_t *sec_tag_list;
	size_t sec_tag_count;
};

struct https_response_capture {
	char *body;
	size_t body_cap;
	size_t body_len;
	uint16_t status_code;
	bool truncated;
	const char *label;
};

static uint8_t http_recv_buf[HTTP_RECV_CHUNK_SIZE];

static const char *const http_common_headers[] = {
	"Connection: close\r\n",
	"User-Agent: Zephyr-HTTP-Client/CustomerFlow\r\n",
	"Accept: application/json\r\n",
	NULL,
};

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

	if (flags < 0) {
		return;
	}

	if (blocking) {
		(void)zsock_fcntl(socket_id, F_SETFL, flags & ~O_NONBLOCK);
	} else {
		(void)zsock_fcntl(socket_id, F_SETFL, flags | O_NONBLOCK);
	}
}

static int http_request_socket_close(int socket)
{
	if (socket >= 0 && zsock_close(socket) != 0) {
		printk("[HTTPS] Socket close failed: %d (%s)\n",
		       -errno, strerror(errno));
	}

	return -1;
}

static int http_request_socket_open(sa_family_t family, const char *hostname,
				    size_t hostname_len, const sec_tag_t *sec_tag_list,
				    size_t sec_tag_count)
{
	int rc;
	int socket_id;
	const int ciphersuites[] = {
		MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		MBEDTLS_TLS1_3_AES_128_GCM_SHA256,
		MBEDTLS_TLS1_3_AES_128_CCM_SHA256,
	};

	if (hostname == NULL || hostname_len == 0U) {
		return -EINVAL;
	}

	socket_id = zsock_socket(family, SOCK_STREAM, IPPROTO_TLS_1_2);
	if (socket_id < 0) {
		printk("[HTTPS] Failed to create socket: %d (%s)\n",
		       -errno, strerror(errno));
		return -errno;
	}

	http_request_socket_set_blocking(socket_id, false);

	rc = zsock_setsockopt(socket_id, SOL_TLS, TLS_CIPHERSUITE_LIST,
			      ciphersuites, sizeof(ciphersuites));
	if (rc < 0) {
		printk("[HTTPS] Failed to set ciphersuite list (%d)\n", -errno);
		goto sock_fail;
	}

	if (sec_tag_list != NULL && sec_tag_count > 0U) {
		rc = zsock_setsockopt(socket_id, SOL_TLS, TLS_SEC_TAG_LIST,
				      sec_tag_list,
				      sec_tag_count * sizeof(sec_tag_t));
		if (rc < 0) {
			printk("[HTTPS] Failed to set TLS_SEC_TAG_LIST: %d\n", -errno);
			goto sock_fail;
		}
	}

	rc = zsock_setsockopt(socket_id, SOL_TLS, TLS_HOSTNAME,
			      hostname, hostname_len);
	if (rc < 0) {
		printk("[HTTPS] Failed to set TLS_HOSTNAME: %d\n", -errno);
		goto sock_fail;
	}

	{
		int enabled = HTTPS_PEER_VERIFY_MODE;

		rc = zsock_setsockopt(socket_id, SOL_TLS, TLS_PEER_VERIFY,
				      &enabled, sizeof(enabled));
	}
	if (rc < 0) {
		printk("[HTTPS] Failed to set TLS_PEER_VERIFY: %d\n", -errno);
		goto sock_fail;
	}

	return socket_id;

sock_fail:
	(void)zsock_close(socket_id);
	return -errno;
}

#if CUSTOMER_REPRO
/* ---- async DNS, like gorm_dns (dns_get_addr_info + callback) ---- */
struct https_dns_ctx {
	struct k_sem done;
	struct sockaddr_in addr;
	bool found;
	int status;
};

static struct https_dns_ctx https_dns;

static void https_dns_cb(enum dns_resolve_status status,
			 struct dns_addrinfo *info, void *user_data)
{
	struct https_dns_ctx *ctx = user_data;

	if (status == DNS_EAI_INPROGRESS) {
		if (info != NULL && info->ai_family == AF_INET) {
			char ip[NET_IPV4_ADDR_LEN];

			net_addr_ntop(AF_INET, &net_sin(&info->ai_addr)->sin_addr,
				      ip, sizeof(ip));
			printk("[HTTPS] dns_resolve_cb: IPv4 address: %s\n", ip);
			if (!ctx->found) {
				memcpy(&ctx->addr, &info->ai_addr, sizeof(ctx->addr));
				ctx->found = true;
			}
		}
		return;
	}

	ctx->status = (status == DNS_EAI_ALLDONE) ? 0 : (int)status;
	k_sem_give(&ctx->done);
}
#endif

static int resolve_endpoint_ipv4(const char *hostname, uint16_t port,
				 struct sockaddr_in *endpoint)
{
	int ret;

	memset(endpoint, 0, sizeof(*endpoint));
	endpoint->sin_family = AF_INET;
	endpoint->sin_port = htons(port);

	if (zsock_inet_pton(AF_INET, hostname, &endpoint->sin_addr) == 1) {
		printk("[HTTPS] %s uses literal IP %s\n", hostname, hostname);
		return 0;
	}

#if CUSTOMER_REPRO
	uint16_t dns_id = 0;
	int64_t t0 = k_uptime_get();

	memset(&https_dns, 0, sizeof(https_dns));
	k_sem_init(&https_dns.done, 0, 1);

	ret = dns_get_addr_info(hostname, DNS_QUERY_TYPE_A, &dns_id,
				https_dns_cb, &https_dns, HTTPS_DNS_TIMEOUT_MS);
	if (ret < 0) {
		/* Customer: "DNS failed to resolve ... with -22" right at DHCP_BOUND */
		printk("[HTTPS] DNS failed to resolve %s with %d\n", hostname, ret);
		return -EHOSTUNREACH;
	}
	printk("[HTTPS] DNS resolve id %u started for %s\n", dns_id, hostname);

	if (k_sem_take(&https_dns.done, K_MSEC(HTTPS_DNS_TIMEOUT_MS + 1000)) != 0) {
		(void)dns_cancel_addr_info(dns_id);
		printk("[HTTPS] DNS resolve %s timed out\n", hostname);
		return -ETIMEDOUT;
	}

	if (https_dns.status != 0 || !https_dns.found) {
		printk("[HTTPS] DNS resolve %s failed: status=%d\n",
		       hostname, https_dns.status);
		return -EHOSTUNREACH;
	}

	memcpy(endpoint, &https_dns.addr, sizeof(*endpoint));
	endpoint->sin_port = htons(port);
	printk("[HTTPS] DNS resolving finished for %s (%lld ms)\n",
	       hostname, k_uptime_get() - t0);
	return 0;
#else
	struct zsock_addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
	};
	struct zsock_addrinfo *res = NULL;

	ret = zsock_getaddrinfo(hostname, NULL, &hints, &res);
	if (ret != 0 || res == NULL) {
		printk("[HTTPS] DNS resolution failed for %s: %d\n", hostname, ret);
		return (ret != 0) ? ret : -EHOSTUNREACH;
	}

	memcpy(endpoint, res->ai_addr, sizeof(*endpoint));
	endpoint->sin_port = htons(port);
	zsock_freeaddrinfo(res);
	return 0;
#endif
}

#if CUSTOMER_REPRO
/* ---- connect completion via Zephyr socket service thread ---- */
static K_EVENT_DEFINE(https_sock_evt);

static void https_sock_svc_handler(struct net_socket_service_event *pev)
{
	uint32_t ev = (uint32_t)pev->event.revents;

	k_event_post(&https_sock_evt, (ev != 0U) ? ev : (uint32_t)ZSOCK_POLLOUT);
}

NET_SOCKET_SERVICE_SYNC_DEFINE_STATIC(https_sock_svc, https_sock_svc_handler, 1);
#endif

static int http_request_socket_connect(int socket_id,
				      const struct sockaddr *endpoint,
				      socklen_t addrlen,
				      int timeout_ms)
{
	int rc;
	int64_t t0 = k_uptime_get();

	printk("[HTTPS] Connect to socket <%d>\n", socket_id);

	rc = zsock_connect(socket_id, endpoint, addrlen);
	if (rc == 0) {
		printk("[HTTPS] Socket (%d) connected immediately (%lld ms)\n",
		       socket_id, k_uptime_get() - t0);
		return 0;
	}

	if (errno != EINPROGRESS) {
		int err = errno;

		/* Customer: "Connect failed: -1 (113: Software caused connection abort)" */
		printk("[HTTPS] Connect failed: -1 (%d: %s) after %lld ms\n",
		       err, strerror(err), k_uptime_get() - t0);
		return -err;
	}

	printk("[HTTPS] Connecting to socket: %d ... (%lld ms)\n",
	       socket_id, k_uptime_get() - t0);

#if CUSTOMER_REPRO
	{
		struct zsock_pollfd fds[1] = {
			{ .fd = socket_id, .events = ZSOCK_POLLOUT, .revents = 0 },
		};
		uint32_t ev;
		int error = 0;
		socklen_t len = sizeof(error);

		k_event_clear(&https_sock_evt, 0xFFFFFFFFU);

		rc = net_socket_service_register(&https_sock_svc, fds, ARRAY_SIZE(fds), NULL);
		if (rc < 0) {
			printk("[HTTPS] socket service register failed: %d\n", rc);
			return rc;
		}

		ev = k_event_wait(&https_sock_evt,
				  ZSOCK_POLLOUT | ZSOCK_POLLERR | ZSOCK_POLLHUP | ZSOCK_POLLNVAL,
				  false, K_MSEC(timeout_ms));

		(void)net_socket_service_unregister(&https_sock_svc);

		if (ev == 0U) {
			printk("[HTTPS] Connection check timeout on socket %d (%d ms)\n",
			       socket_id, timeout_ms);
			return -ETIMEDOUT;
		}

		if (ev & (ZSOCK_POLLERR | ZSOCK_POLLHUP | ZSOCK_POLLNVAL)) {
			(void)zsock_getsockopt(socket_id, SOL_SOCKET, SO_ERROR, &error, &len);
			printk("[HTTPS] Connection check failed: revents=0x%x SO_ERROR=%d (%lld ms)\n",
			       ev, error, k_uptime_get() - t0);
			return (error != 0) ? -error : -ECONNABORTED;
		}

		rc = zsock_getsockopt(socket_id, SOL_SOCKET, SO_ERROR, &error, &len);
		if (rc == 0 && error != 0) {
			printk("[HTTPS] Connect SO_ERROR=%d (%lld ms)\n",
			       error, k_uptime_get() - t0);
			return -error;
		}

		printk("[HTTPS] Socket (%d) connected (%lld ms)\n",
		       socket_id, k_uptime_get() - t0);
		return 0;
	}
#else
	int elapsed_ms = 0;

	while (elapsed_ms < timeout_ms) {
		struct zsock_pollfd pfd = {
			.fd = socket_id,
			.events = ZSOCK_POLLOUT,
			.revents = 0,
		};
		int error = 0;
		socklen_t len = sizeof(error);

		rc = zsock_poll(&pfd, 1, 250);
		if (rc < 0) {
			return -errno;
		}

		elapsed_ms += 250;
		if (rc == 0 || (pfd.revents & ZSOCK_POLLOUT) == 0) {
			continue;
		}

		rc = zsock_getsockopt(socket_id, SOL_SOCKET, SO_ERROR, &error, &len);
		if (rc == 0 && error == 0) {
			return 0;
		}

		printk("[HTTPS] Connect SO_ERROR=%d after %d ms\n",
		       error, elapsed_ms);
		return (error != 0) ? -error : -EIO;
	}

	return -ETIMEDOUT;
#endif
}

static int http_response_capture_cb(struct http_response *rsp,
				    enum http_final_call final_data,
				    void *user_data)
{
	struct https_response_capture *capture = user_data;
	size_t copy_len;
	size_t room;

	if (capture == NULL || rsp == NULL) {
		return 0;
	}

	capture->status_code = rsp->http_status_code;
	printk("[HTTPS] %s response: final=%d status=%u frag=%u processed=%u\n",
	       capture->label,
	       final_data == HTTP_DATA_FINAL ? 1 : 0,
	       capture->status_code,
	       (unsigned)rsp->body_frag_len,
	       (unsigned)rsp->processed);

	if (rsp->body_frag_start == NULL || rsp->body_frag_len == 0U ||
	    capture->body == NULL || capture->body_cap == 0U) {
		return 0;
	}

	room = capture->body_cap - capture->body_len;
	if (room <= 1U) {
		capture->truncated = true;
		return 0;
	}

	copy_len = MIN(rsp->body_frag_len, room - 1U);
	memcpy(capture->body + capture->body_len, rsp->body_frag_start, copy_len);
	capture->body_len += copy_len;
	capture->body[capture->body_len] = '\0';

	if (copy_len < rsp->body_frag_len) {
		capture->truncated = true;
	}

	return 0;
}

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

static bool parse_mqtt_cfg_from_body(const char *body, struct https_mqtt_cfg *cfg)
{
	if (cfg == NULL) {
		return false;
	}

	memset(cfg, 0, sizeof(*cfg));
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

	if (json_copy_string_field(body, "mqtt_ca_pem", cfg->ca_pem,
				   sizeof(cfg->ca_pem)) &&
	    json_copy_string_field(body, "mqtt_client_cert_pem",
				   cfg->client_cert_pem,
				   sizeof(cfg->client_cert_pem)) &&
	    json_copy_string_field(body, "mqtt_private_key_pem",
				   cfg->private_key_pem,
				   sizeof(cfg->private_key_pem))) {
		cfg->ca_pem_len = strlen(cfg->ca_pem) + 1U;
		cfg->client_cert_pem_len = strlen(cfg->client_cert_pem) + 1U;
		cfg->private_key_pem_len = strlen(cfg->private_key_pem) + 1U;
		cfg->certs_valid = true;
		printk("[HTTPS] Parsed MQTT PEMs: ca=%u client=%u key=%u\n",
		       (unsigned)cfg->ca_pem_len,
		       (unsigned)cfg->client_cert_pem_len,
		       (unsigned)cfg->private_key_pem_len);
	} else {
		printk("[HTTPS] MQTT PEMs missing - will use flash defaults\n");
	}

	return true;
}

static uint32_t https_backoff_ms(void)
{
	return HTTPS_BACKOFF_MIN_MS + (sys_rand32_get() % HTTPS_BACKOFF_JITTER_MS);
}

/*
 * One HTTPS transaction with the customer retry policy:
 *   cycle:   DNS -> (connect attempt x HTTPS_CONNECT_ATTEMPTS) -> request
 *   failure: close socket, backoff 1.0-1.9 s, next cycle with fresh DNS
 * Every connect attempt uses a brand-new socket created right after the
 * previous close, so the RA6W1 re-uses the same remote fd - exactly the
 * pattern of the customer log ("Remote socket close fd=1" -> new socket).
 */
static int https_execute_request(const struct https_request_desc *desc,
				 struct https_response_capture *capture)
{
	struct sockaddr_in endpoint;
	char port[8];
	int ret = -EIO;
	bool creds_loaded = false;
	int cycles = CUSTOMER_REPRO ? HTTPS_REQUEST_CYCLES : 1;

	if (desc == NULL || capture == NULL) {
		return -EINVAL;
	}

#if !USE_TLS_VERIFY_NONE
	ret = setup_https_credentials();
	if (ret < 0) {
		return ret;
	}
	creds_loaded = true;
#endif

	for (int cycle = 1; cycle <= cycles; cycle++) {
		struct http_request request = { 0 };
		int socket_id = -1;
		int64_t t_req = k_uptime_get();

		if (cycle > 1) {
			uint32_t backoff = https_backoff_ms();

			printk("[HTTPS] %s backoff %u ms (cycle %d/%d)\n",
			       desc->label, backoff, cycle, cycles);
			k_msleep(backoff);
		}

		capture->body_len = 0;
		capture->status_code = 0;
		capture->truncated = false;
		if (capture->body != NULL && capture->body_cap > 0U) {
			capture->body[0] = '\0';
		}

		printk("[HTTPS] %s request: https://%s:%u%s (cycle %d)\n",
		       desc->label, desc->hostname, desc->port, desc->path, cycle);

		ret = resolve_endpoint_ipv4(desc->hostname, desc->port, &endpoint);
		if (ret < 0) {
			printk("[HTTPS] DNS lookup (%s) failed: %d\n", desc->hostname, ret);
			continue;
		}

		for (int attempt = 1; attempt <= HTTPS_CONNECT_ATTEMPTS; attempt++) {
			socket_id = http_request_socket_open(endpoint.sin_family,
							     desc->hostname,
							     strlen(desc->hostname) + 1U,
							     desc->sec_tag_list,
							     desc->sec_tag_count);
			if (socket_id < 0) {
				ret = socket_id;
				printk("[HTTPS] %s socket open failed: %d\n", desc->label, ret);
				continue;
			}

			ret = http_request_socket_connect(socket_id,
							 (const struct sockaddr *)&endpoint,
							 sizeof(endpoint),
							 HTTPS_CONNECT_TIMEOUT_MS);
			if (ret == 0) {
				break;
			}

			printk("[HTTPS] %s connect attempt %d/%d failed: %d\n",
			       desc->label, attempt, HTTPS_CONNECT_ATTEMPTS, ret);
			/* Customer closes and immediately opens a new socket. */
			socket_id = http_request_socket_close(socket_id);
#if !CUSTOMER_REPRO
			k_msleep(200);
#endif
		}

		if (ret < 0 || socket_id < 0) {
			printk("[HTTPS] %s: connect failed, HTTP response status code 0\n",
			       desc->label);
			socket_id = http_request_socket_close(socket_id);
			if (ret == 0) {
				ret = -ENOTCONN;
			}
			continue;
		}

		http_request_socket_set_blocking(socket_id, true);
		snprintk(port, sizeof(port), "%u", desc->port);

		request.method = desc->method;
		request.url = desc->path;
		request.host = desc->hostname;
		request.port = port;
		request.protocol = "HTTP/1.1";
		request.response = http_response_capture_cb;
		request.recv_buf = http_recv_buf;
		request.recv_buf_len = sizeof(http_recv_buf);
		request.header_fields = NULL;
		request.optional_headers = (const char **)http_common_headers;

		if (desc->payload != NULL) {
			request.payload = desc->payload;
			request.payload_len = strlen(desc->payload);
			request.content_type_value = desc->content_type;
		}

		ret = http_client_req(socket_id, &request, HTTPS_REQUEST_TIMEOUT_MS, capture);
		socket_id = http_request_socket_close(socket_id);

		if (ret < 0) {
			printk("[HTTPS] %s request failed: %d\n", desc->label, ret);
			continue;
		}

		printk("[HTTPS] %s complete: status=%u body_len=%u truncated=%d total=%lld ms (cycle %d)\n",
		       desc->label,
		       capture->status_code,
		       (unsigned)capture->body_len,
		       capture->truncated ? 1 : 0,
		       k_uptime_get() - t_req, cycle);
		ret = 0;
		break;
	}

	if (creds_loaded) {
		teardown_https_credentials();
	}
#if !CUSTOMER_REPRO
	k_msleep(200);
#endif
	return ret;
}

int https_phase1_get(struct https_mqtt_cfg *cfg)
{
	const sec_tag_t https_sec_tag_list[] = {
		TLS_TAG_HTTPS_CA_CERTIFICATE,
		HTTPS_CLIENT_CERT_TAG,
	};
	struct https_request_desc req = {
		.label = "bootstrap GET",
		.hostname = HTTPS_BOOTSTRAP_SERVER,
		.port = HTTPS_BOOTSTRAP_PORT,
		.path = HTTPS_BOOTSTRAP_PATH,
		.method = HTTP_GET,
#if USE_TLS_VERIFY_NONE
		.sec_tag_list = NULL,
		.sec_tag_count = 0,
#else
		.sec_tag_list = https_sec_tag_list,
		.sec_tag_count = ARRAY_SIZE(https_sec_tag_list),
#endif
	};
	static char response_body[HTTP_MAX_BODY_SIZE];
	struct https_response_capture capture = {
		.body = response_body,
		.body_cap = sizeof(response_body),
		.body_len = 0,
		.status_code = 0,
		.truncated = false,
		.label = req.label,
	};
	int ret;

	if (cfg != NULL) {
		memset(cfg, 0, sizeof(*cfg));
	}

	response_body[0] = '\0';
	ret = https_execute_request(&req, &capture);
	if (ret < 0) {
		return ret;
	}

	if (cfg != NULL && !parse_mqtt_cfg_from_body(response_body, cfg)) {
		printk("[HTTPS] MQTT cfg parse failed (MQTT will use defaults)\n");
	}

	return 0;
}

int https_onboard_post_probe(const struct https_mqtt_cfg *cfg)
{
	const sec_tag_t https_sec_tag_list[] = {
		TLS_TAG_HTTPS_CA_CERTIFICATE,
		HTTPS_CLIENT_CERT_TAG,
	};
	char payload[1400];
	char csr_fill[HTTPS_ONBOARD_CSR_FILL + 1U];
	static char response_body[1024];
	struct https_request_desc req = {
		.label = "onboard POST",
		.hostname = HTTPS_ONBOARD_SERVER,
		.port = HTTPS_ONBOARD_PORT,
		.path = HTTPS_ONBOARD_PATH,
		.method = HTTP_POST,
		.content_type = "application/json",
#if USE_TLS_VERIFY_NONE
		.sec_tag_list = NULL,
		.sec_tag_count = 0,
#else
		.sec_tag_list = https_sec_tag_list,
		.sec_tag_count = ARRAY_SIZE(https_sec_tag_list),
#endif
	};
	struct https_response_capture capture = {
		.body = response_body,
		.body_cap = sizeof(response_body),
		.body_len = 0,
		.status_code = 0,
		.truncated = false,
		.label = req.label,
	};
	const char *client_id = (cfg != NULL && cfg->valid) ? cfg->client_id : "pnet-mt-client";
	const char *mqtt_host = (cfg != NULL && cfg->valid) ? cfg->host : "unprovisioned";
	uint16_t mqtt_port = (cfg != NULL && cfg->valid) ? cfg->port : 0U;
	int ret;

	memset(csr_fill, 'A', sizeof(csr_fill) - 1U);
	csr_fill[sizeof(csr_fill) - 1U] = '\0';

	snprintk(payload, sizeof(payload),
		 "{\"deviceId\":\"J3APC0006A\","
		 "\"clientId\":\"%s\","
		 "\"mqttHost\":\"%s\","
		 "\"mqttPort\":%u,"
		 "\"transport\":\"zephyr-http-client\","
		 "\"csr\":\"%s\"}",
		 client_id, mqtt_host, mqtt_port, csr_fill);

	req.payload = payload;
	response_body[0] = '\0';

	ret = https_execute_request(&req, &capture);
	if (ret < 0) {
		return ret;
	}

	if (capture.status_code < 200U || capture.status_code >= 300U) {
		printk("[HTTPS] Onboard POST returned HTTP %u (transport still OK)\n",
		       capture.status_code);
	}

	if (capture.body_len > 0U) {
		printk("[HTTPS] Onboard response body: %s\n", response_body);
	}

	return 0;
}
