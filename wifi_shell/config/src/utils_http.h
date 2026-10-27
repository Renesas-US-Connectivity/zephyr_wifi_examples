#ifndef UTILS_HTTP_H
#define UTILS_HTTP_H

#include <zephyr/net/net_ip.h>

int utils_http_get(const char *url, uint16_t port, const char *path);

int utils_https_get(const char *host, uint16_t port, const char *url,
	uint8_t *recv_buf, size_t recv_buf_len,
	const uint8_t *client_cert, size_t client_cert_len,
	const uint8_t *client_key, size_t client_key_len,
	const uint8_t *ca_cert, size_t ca_cert_len);

#endif // UTILS_HTTP_H
