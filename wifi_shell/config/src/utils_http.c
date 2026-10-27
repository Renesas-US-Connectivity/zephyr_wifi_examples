#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/http/client.h>
#include <zephyr/logging/log.h>

#include <zephyr/net/tls_credentials.h>
#include <mbedtls/ssl_ciphersuites.h>

#include "utils_dns.h"

LOG_MODULE_REGISTER(utils_http, LOG_LEVEL_DBG);

struct http_response_ctx {
	char *body;
	size_t body_len;
	size_t body_cur;
};

static char http_response_body[4096];

static int response_cb(struct http_response *rsp,
			 enum http_final_call final_data,
			 void *user_data)
{
	struct http_response_ctx *ctx = user_data;

	if (rsp->body_frag_start && rsp->body_frag_len) {
		LOG_INF("Received %zu bytes of body data", rsp->body_frag_len);

		if (ctx->body_cur + rsp->body_frag_len > ctx->body_len) {
			LOG_ERR("HTTP response body overflow");
			return -1;
		}

		if (ctx->body) {
			memcpy(ctx->body + ctx->body_cur, rsp->body_frag_start, rsp->body_frag_len);
		}
		ctx->body_cur += rsp->body_frag_len;
	}

	if (final_data == HTTP_DATA_FINAL) {
		LOG_INF("HTTP response complete, status: %s, total body: %zu bytes",
			rsp->http_status, ctx->body_cur);
	}
	return 0;
}

#define CA_CERT_TAG 1
#define CLIENT_CERT_TAG 2

int set_https_params(int sock, const char *hostname,
	const uint8_t *ca_cert, size_t ca_cert_len,
	const uint8_t *client_cert, size_t client_cert_len,
	const uint8_t *client_key, size_t client_key_len)
{
	sec_tag_t sec_tag_list[2] = {0,};
	int sec_tag_list_cnt = 0;
	int ret;

	// Set Server Name Indication (SNI) name
	ret = zsock_setsockopt(sock, SOL_TLS, TLS_HOSTNAME, hostname, strlen(hostname));
	if (ret < 0) {
		LOG_ERR("Failed to set TLS_SNI: %d", -errno);
		return -1;
	}

	const int ciphersuites[] = {
		MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		MBEDTLS_TLS1_3_AES_128_GCM_SHA256,
		MBEDTLS_TLS1_3_AES_128_CCM_SHA256,
	};
	ret = zsock_setsockopt(sock, SOL_TLS, TLS_CIPHERSUITE_LIST,
			ciphersuites, sizeof(ciphersuites));
	if (ret < 0) {
		LOG_ERR("Failed to set ciphersuite list option (%d)", -errno);
		return -1;
	}

	if (ca_cert_len) {
		int enabled = TLS_PEER_VERIFY_REQUIRED;
		LOG_INF("Setting TLS peer verification to required");
		ret = zsock_setsockopt(sock, SOL_TLS, TLS_PEER_VERIFY, &enabled, sizeof(enabled));
		if (ret < 0) {
			LOG_ERR("Failed to set TLS_PEER_VERIFY: %d", -errno);
			return -1;
		}
	} else {
		int enabled = TLS_PEER_VERIFY_NONE;
		LOG_INF("Setting TLS peer verification to none");
		ret = zsock_setsockopt(sock, SOL_TLS, TLS_PEER_VERIFY, &enabled, sizeof(enabled));
		if (ret < 0) {
			LOG_ERR("Failed to set TLS_PEER_VERIFY: %d", -errno);
			return -1;
		}

	}

	if (ca_cert_len) {
		LOG_INF("Adding Peer CA certificate: %d bytes", ca_cert_len);
		sec_tag_list[sec_tag_list_cnt++] = CA_CERT_TAG;
		ret = tls_credential_add(CA_CERT_TAG, TLS_CREDENTIAL_CA_CERTIFICATE,
				ca_cert, ca_cert_len);
		if (ret < 0) {
			LOG_ERR("Failed to add peer CA cert %d", ret);
			return -1;
		}
	}

	if (client_cert_len) {
		LOG_INF("Adding client certificate: %d bytes", client_cert_len);
		sec_tag_list[sec_tag_list_cnt++] = CLIENT_CERT_TAG;
		ret = tls_credential_add(CLIENT_CERT_TAG,
			TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
			client_cert, client_cert_len);
		if (ret < 0) {
			LOG_ERR("Failed to register client cert %d", ret);
			return -1;
		}

		LOG_INF("Adding client private key: %d bytes", client_key_len);
		ret = tls_credential_add(CLIENT_CERT_TAG,
				TLS_CREDENTIAL_PRIVATE_KEY,
				client_key, client_key_len);
		if (ret < 0) {
			LOG_ERR("Failed to register client private key %d", ret);
			return -1;
		}
	}


	if (sec_tag_list_cnt > 0) {
		LOG_INF("Setting TLS_SEC_TAG_LIST with %d tags", sec_tag_list_cnt);
		ret = zsock_setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST,
				sec_tag_list, sec_tag_list_cnt * sizeof(sec_tag_t));
		if (ret < 0) {
			LOG_ERR("Failed to set TLS_SEC_TAG_LIST: %d", -errno);
			return -1;
		}
	}
	return 0;
}

static void del_https_param(void)
{
	tls_credential_delete(CA_CERT_TAG, TLS_CREDENTIAL_CA_CERTIFICATE);
	tls_credential_delete(CLIENT_CERT_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE);
	tls_credential_delete(CLIENT_CERT_TAG, TLS_CREDENTIAL_PRIVATE_KEY);
}

static int utils_https_get_internal(int proto, const char *host, uint16_t port, const char *url,
	uint8_t *recv_buf, size_t recv_buf_len,
	const uint8_t *ca_cert, size_t ca_cert_len,
	const uint8_t *client_cert, size_t client_cert_len,
	const uint8_t *client_key, size_t client_key_len)
{
	int ret;
	int sock = -1;
	struct sockaddr_in sockaddr = { 0 };
	struct in_addr addr[1];

	struct http_response_ctx ctx = { .body = recv_buf, .body_len = recv_buf_len };
	struct http_request req = {0, };

	if (dns_resolve(host, addr, 1) <= 0) {
		LOG_ERR("Failed to resolve host %s", host);
		return -EHOSTUNREACH;
	}

	LOG_INF("Socket creating %d", proto);

	sock = zsock_socket(AF_INET, SOCK_STREAM, proto);
	if (sock < 0) {
		LOG_ERR("Failed to create socket (%d/%d)", sock, errno);
		return -errno;
	}
	LOG_INF("Socket created");

	if (proto == IPPROTO_TLS_1_2) {
		LOG_INF("Setting HTTPS parameters for host %s", host);
		ret = set_https_params(sock, host, ca_cert, ca_cert_len, client_cert, client_cert_len, client_key, client_key_len);
		if (ret < 0) {
			LOG_ERR("Failed to set HTTPS parameters");
			goto out_close;
		}
	}

	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(port);
	sockaddr.sin_addr = addr[0];
	char hr_addr[NET_IPV6_ADDR_LEN];
	net_addr_ntop(sockaddr.sin_family, &sockaddr.sin_addr, hr_addr, sizeof(hr_addr));
	LOG_INF("Connect to [%s %s:%d]", host, hr_addr, port);
	ret = zsock_connect(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
	if (ret < 0) {
		LOG_ERR("Failed to connect to %s:%u (%d)", host, port, errno);
		goto out_close;
	}

	req.method = HTTP_GET;
	req.url = url;
	req.host = host;
	req.protocol = "HTTP/1.1";
	req.response = response_cb;
	req.recv_buf = http_response_body;;
	req.recv_buf_len = sizeof(http_response_body);

	ret = http_client_req(sock, &req, 5000, &ctx);
	if (ret < 0) {
		LOG_ERR("HTTP request failed (%d)", ret);
		goto out_close;
	}

	ret = ctx.body_cur;

out_close:
	del_https_param();
	if (sock >= 0) {
		zsock_close(sock);
	}
	return ret;
}

int utils_http_get(const char *host, uint16_t port, const char *url)
{
	return utils_https_get_internal(IPPROTO_TCP, host, port, url, NULL, 0, NULL, 0, NULL, 0, NULL, 0);
}

int utils_https_get(const char *host, uint16_t port, const char *url,
	uint8_t *recv_buf, size_t recv_buf_len,
	const uint8_t *ca_cert, size_t ca_cert_len,
	const uint8_t *client_cert, size_t client_cert_len,
	const uint8_t *client_key, size_t client_key_len)
{
	return utils_https_get_internal(IPPROTO_TLS_1_2, host, port, url,
		recv_buf, recv_buf_len,
		ca_cert, ca_cert_len,
		client_cert, client_cert_len,
		client_key, client_key_len);
}
