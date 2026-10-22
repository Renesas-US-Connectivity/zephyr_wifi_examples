#include <assert.h>
#include <zephyr/logging/log.h>
#include "utils_iface.h"

LOG_MODULE_REGISTER(utils_iface, LOG_LEVEL_DBG);

static struct ctx {
	bool connected;
} ctx;

int iface_connect(const char *ssid, const char *psk, int timeout_ms)
{
#ifdef CONFIG_BOARD_NATIVE_SIM
	return 0;
#endif
	struct net_if *iface = net_if_get_default();
	int retries = 15;

	do {
		struct net_if_ipv4 *ipv4;
		struct net_if_addr *unicast;

		if (!net_if_flag_is_set(iface, NET_IF_IPV4)) {
			LOG_ERR("Interface does not support IPv4");
			return -1;
		}

		ipv4 = iface->config.ip.ipv4;
		ARRAY_FOR_EACH(ipv4->unicast, i) {
			unicast = &ipv4->unicast[i].ipv4;
			if (unicast->is_used) {
				LOG_INF("Got ipv4 addr");
				ctx.connected = true;
				return 0;
			}
		}
		k_msleep(1000);
	} while(retries-- > 0);

	LOG_INF("Failed to connect");
	return -1;
}

void iface_connect_if_needed(void)
{
#ifdef CONFIG_BOARD_NATIVE_SIM
	return;
#endif

	if (ctx.connected) {
		return;
	}
	assert(iface_connect(NULL, NULL, 20000) == 0);
}

int iface_disconnect(void)
{
	ctx.connected = false;
	LOG_INF("Disconnect");
	return 0;
}

int iface_status(void)
{
	LOG_INF("NOP");
	return 0;
}

void iface_ensure_up(void)
{
}

int iface_get_version(struct wifi_version *fw_version)
{
	static const char *eth_mock_ver = "v1.0.0";

	fw_version->drv_version = eth_mock_ver;
	fw_version->fw_version = eth_mock_ver;
	return 0;
}


/* USB eth is buggy. Just stub up / down*/
int iface_up(void)
{
	LOG_INF("Interface up");
	return 0;
}

int iface_down(void)
{
	LOG_INF("Interface down");
	return 0;
}

int iface_ps_config(void)
{
	return 0;
}

int iface_ps(bool enable)
{
	return 0;
}
