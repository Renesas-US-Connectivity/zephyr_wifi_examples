#include <zephyr/ztest.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/wifi_mgmt.h>

#include "utils_iface.h"
#include "utils_dns.h"
#include "utils_iconfig.h"

LOG_MODULE_REGISTER(net_tests, LOG_LEVEL_DBG);
ZTEST_SUITE(net_tests, NULL, NULL, NULL, NULL, NULL);

ZTEST(net_tests, test_version)
{
	for (int i = 0; i < 5; i++) {
		int ret;
		struct wifi_version fw_version = {};

		ret = iface_up();
		zassert_equal(ret, 0, "iface_up failed");

		ret = iface_get_version(&fw_version);
		zassert_equal(ret, 0, "iface_get_version failed");
		LOG_INF("WiFi firmware version: %s", fw_version.drv_version);

		ret = iface_down();
		zassert_equal(ret, 0, "iface_down failed");
	}
}

ZTEST(net_tests, test_dns)
{
	for (int i = 0; i < 5; i++) {
		const char *hostname = "www.sunet.se";
		struct in_addr results[4];
		size_t results_len = ARRAY_SIZE(results), results_cnt;

		iface_connect_if_needed();
		results_cnt = dns_resolve(hostname, results, results_len);
		LOG_INF("Resolved %d addresses for %s", results_cnt, hostname);
		zassert_true(results_cnt > 0, "Failed to resolve %s", hostname);

		int ret = iface_down();
		zassert_equal(ret, 0, "iface_down failed");
		k_sleep(K_SECONDS(3));
	}
}

ZTEST(net_tests, test_iconfig)
{
	for (int i = 0; i < 3; i++) {

		iface_connect_if_needed();
		int ret = utils_iconfig_fetch();
		zassert_equal(ret, 0, "iconfig_fetch failed");

		ret = iface_down();
		zassert_equal(ret, 0, "iface_down failed");
	}
}
