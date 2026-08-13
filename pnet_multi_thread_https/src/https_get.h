/*
 * Phase 4: HTTPS GET provisions MQTT host/port/client_id plus PEM certs.
 * Peer verify disabled for self-signed HTTPS bring-up.
 */
#ifndef HTTPS_GET_H
#define HTTPS_GET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HTTPS_MQTT_HOST_MAX 64
#define HTTPS_MQTT_ID_MAX   32
/* Room for typical 2K RSA PEM (+ header/footer). */
#define HTTPS_MQTT_PEM_MAX  2048

struct https_mqtt_cfg {
	char host[HTTPS_MQTT_HOST_MAX];
	char client_id[HTTPS_MQTT_ID_MAX];
	uint16_t port;
	bool valid;       /* host/port/client_id parsed */
	bool certs_valid; /* CA + client cert + key parsed */

	char ca_pem[HTTPS_MQTT_PEM_MAX];
	size_t ca_pem_len;
	char client_cert_pem[HTTPS_MQTT_PEM_MAX];
	size_t client_cert_pem_len;
	char private_key_pem[HTTPS_MQTT_PEM_MAX];
	size_t private_key_pem_len;
};

/**
 * HTTPS GET to LAN provision server.
 * Fills @p cfg with MQTT endpoint and optional PEM credentials from JSON.
 * Always closes the TLS socket before return.
 *
 * @return 0 on HTTP/TLS success, negative errno-style value on transport failure
 */
int https_phase1_get(struct https_mqtt_cfg *cfg);

#ifdef __cplusplus
}
#endif

#endif /* HTTPS_GET_H */
