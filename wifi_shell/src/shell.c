#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/shell/shell.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>

#include "utils_iface.h"
#include "utils_dns.h"
#include "utils_http.h"
#include "utils_iconfig.h"
#include "env_config.h"

LOG_MODULE_REGISTER(nt_shell, LOG_LEVEL_DBG);

static int cmd_connect(const struct shell *shell, size_t argc, char **argv)
{
	const char *ssid;
	const char *psk;

	if (argc == 1) {
		shell_print(shell, "Connecting with default SSID and PSK from env_config.h");
		ssid = NULL;
		psk = NULL;
	} else if (argc == 3) {
		ssid = argv[1];
		psk = argv[2];
	} else {
		shell_error(shell, "Usage: wifi connect [SSID] [PSK]");
		return -1;
	}
	iface_ensure_up();
	iface_connect(ssid, psk, 40000);
	return 0;
}

static int cmd_disconnect(const struct shell *shell, size_t argc, char **argv)
{
	iface_disconnect();
	return 0;
}

static int cmd_status(const struct shell *shell, size_t argc, char **argv)
{
	iface_status();
	return 0;
}

static int cmd_ver(const struct shell *shell, size_t argc, char **argv)
{
	int ret;
	struct wifi_version fw_version = {0,};

	ret = iface_get_version(&fw_version);
	if (ret != 0) {
		shell_error(shell, "Failed to get WiFi version: %d", ret);
		return -1;
	}
	LOG_INF("WiFi driver/firmware version: [%s/%s]",
		fw_version.drv_version ? fw_version.drv_version : "N/A",
		fw_version.fw_version ? fw_version.fw_version : "N/A");
	return 0;
}

static int cmd_ps(const struct shell *shell, size_t argc, char **argv)
{
	if (strcmp(argv[1], "cfg") == 0) {
		if (iface_ps_config() != 0) {
			shell_error(shell, "Failed to configure power save");
			return -1;
		}
		shell_print(shell, "Power save configured");
		return 0;
	}

	if (strcmp(argv[1], "on") == 0 || strcmp(argv[1], "off") == 0) {
		bool enable = (strcmp(argv[1], "on") == 0);
		if (iface_ps(enable) != 0) {
			shell_error(shell, "Failed to set power save mode");
			return -1;
		}
		shell_print(shell, "Power save %s", enable ? "enabled" : "disabled");
		return 0;
	}


	shell_error(shell, "Usage: wifi ps <cfg|on|off>");
	return -1;
}

static int cmd_resolve(const struct shell *shell, size_t argc, char **argv)
{
	const char *hostname;
	struct in_addr results[4];
	int results_cnt;

	if (argc == 1) {
		shell_error(shell, "Usage: wifi resolve <hostname>");
		return -1;
	}

	hostname = argv[1];
	results_cnt = dns_resolve(hostname, results, ARRAY_SIZE(results));
	if (results_cnt <= 0) {
		shell_error(shell, "Failed to resolve %s", hostname);
		return -1;
	}

	shell_print(shell, "%s:", hostname);
	for (size_t i = 0; i < results_cnt; i++) {
		char hr_addr[NET_IPV4_ADDR_LEN];
		net_addr_ntop(AF_INET, &results[i], hr_addr, sizeof(hr_addr));
		shell_print(shell, "A: %s", hr_addr);
	}
	return 0;
}

#define DT_DRV_COMPAT renesas_erpc_wifi_spi
static int cmd_reset_float(const struct shell *shell, size_t argc, char **argv)
{
#if defined(CONFIG_DT_HAS_RENESAS_ERPC_WIFI_SPI_ENABLED)
	const struct gpio_dt_spec wifi_reset = GPIO_DT_SPEC_GET(DT_DRV_INST(0), reset_gpios);
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (!device_is_ready(wifi_reset.port)) {
		printk("WiFi reset pin not ready\n");
		return 0;
	}

	int ret = gpio_pin_configure_dt(&wifi_reset, GPIO_INPUT);
	printk("WiFi reset pin float ret: %d\n", ret);
	return 0;
#else
	printk("No reset on this hw\n");
	return -1;
#endif
}

static int cmd_wifi_regulator(const struct shell *shell, size_t argc, char **argv)
{
#if defined(CONFIG_DT_HAS_RENESAS_ERPC_WIFI_SPI_ENABLED)
	const struct gpio_dt_spec wifi_reg = GPIO_DT_SPEC_GET_OR(DT_NODELABEL(wifi_enable), gpios, {});
	int enable = (strcmp(argv[1], "on") == 0);

	if (!device_is_ready(wifi_reg.port)) {
		printk("WiFi regulator pin not available\n");
		return 0;
	}

	int ret = gpio_pin_configure_dt(&wifi_reg, GPIO_OUTPUT);
	ret = gpio_pin_set_dt(&wifi_reg, !enable);

	printk("WiFi regulator pin float ret: %d\n", ret);
	return 0;
#else
	printk("No wifi regulator on this hw\n");
	return -1;
#endif
}


static int cmd_http_get(const struct shell *shell, size_t argc, char **argv)
{
	utils_http_get("www.google.com", 80, "/");
	return 0;
}

static int cmd_https_get(const struct shell *shell, size_t argc, char **argv)
{
	utils_https_get("www.google.com", 443, "/", NULL, 0, NULL, 0, NULL, 0, NULL, 0);
	return 0;
}

static int cmd_iconfig_fetch(const struct shell *shell, size_t argc, char **argv)
{
	return utils_iconfig_fetch();
}

SHELL_STATIC_SUBCMD_SET_CREATE(nt_subcmds,
		SHELL_CMD_ARG(ver, NULL, "Version",
			cmd_ver, 1, 0),
		SHELL_CMD_ARG(connect, NULL, "Connect",
			cmd_connect, 1, 2),
		SHELL_CMD_ARG(disconnect, NULL, "Disconnect",
			cmd_disconnect, 1, 0),
		SHELL_CMD_ARG(status, NULL, "Interface status",
			cmd_status, 1, 0),
		SHELL_CMD_ARG(ps, NULL, "Power Save",
			cmd_ps, 2, 0),
		SHELL_CMD_ARG(reset_float, NULL, "Reset float",
			cmd_reset_float, 1, 0),
		SHELL_CMD_ARG(regulator, NULL, "Control wifi regulator",
			cmd_wifi_regulator, 2, 0),
		SHELL_CMD_ARG(disconnect, NULL, "Disconnect",
			cmd_disconnect, 1, 0),
		SHELL_CMD_ARG(resolve, NULL, "DNS resolve",
			cmd_resolve, 1, 2),
		SHELL_CMD_ARG(http_get, NULL, "HTTP GET",
			cmd_http_get, 1, 0),
		SHELL_CMD_ARG(https_get, NULL, "HTTPS GET",
			cmd_https_get, 1, 0),
		SHELL_CMD_ARG(iconfig_fetch, NULL, "Fetch iconfig",
			cmd_iconfig_fetch, 1, 0),
		SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(nt, &nt_subcmds,
		"nt commands", NULL);

