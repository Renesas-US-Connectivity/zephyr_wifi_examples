#include <zephyr/logging/log.h>

#define SERIAL "J3APC0006A"

#include "../resources/ca_iconfig.der.h"
#include "../resources/J3APC0006A_cert.h"
#include "../resources/J3APC0006A_key.h"

#include "utils_http.h"

LOG_MODULE_REGISTER(utils_iconfig, LOG_LEVEL_DBG);

static char iconfig_json[4096];

int utils_iconfig_fetch(void)
{
	const char *host = "pin-iconfig.aaecosystem.com";
	const char *url = "/devices/" SERIAL;
	int ret;

	ret = utils_https_get(host, 443, url, iconfig_json, sizeof(iconfig_json),
		ca_iconfig_der, ca_iconfig_der_len,
		J3APC0006A_cert_der, J3APC0006A_cert_der_len,
		J3APC0006A_key_bin, J3APC0006A_key_bin_len);
	if (ret < 0) {
		LOG_ERR("Failed to fetch iconfig: %d", ret);
		return ret;
	} else {
		LOG_DBG("Fetched iconfig [%d] bytes", ret);
		iconfig_json[ret] = '\0';
		iconfig_json[64] = '\0';
		LOG_DBG("Iconfig JSON (truncated to 64 bytes): %s", iconfig_json);
	}
	return 0;
}

