
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/ethernet_mgmt.h>
#ifdef CONFIG_DNS_RESOLVER
#include <zephyr/net/dns_resolve.h>
#endif
#include <zephyr/net/socket.h>
#include <zephyr/shell/shell.h>
#include <zephyr/net/socket_offload.h>
#include <zephyr/sys/__assert.h>
#include <zephyr/sys/atomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <zephyr/autoconf.h>

#if DT_NODE_EXISTS(DT_NODELABEL(cdc_ncm_eth0))
#define HAS_USB_ETH
#include <sample_usbd.h>
#include <zephyr/net/net_config.h>
#endif


#ifdef CONFIG_SHELL

static int cmd_init(const struct shell *shell, size_t argc, char **argv)
{
	(void)shell;
	(void)argc;
	(void)argv;

	printk("Initializing wifi...\n");
	struct net_if *iface = net_if_get_default();
	net_if_up(iface);
	printk("wifi initialize successful: %s\n", net_if_get_config(iface)->name);
	printk("socket_offload_dns: %d\n", socket_offload_dns_is_enabled());
	//socket_offload_dns_enable(false);
	//printk("socket_offload_dns2: %d\n", socket_offload_dns_is_enabled());
	return 0;
}

static int tsock = -1;

struct pnet_test_stats {
	uint32_t pass;
	uint32_t fail;
	int32_t last_err;
	int64_t min_latency_ms;
	int64_t max_latency_ms;
	int64_t total_latency_ms;
};

#ifdef CONFIG_DNS_RESOLVER
static struct {
	struct k_sem done_sem;
	atomic_t done;
	int status;
} g_dns_async_ctx;
#endif

struct pnet_suite_summary {
	uint32_t pass;
	uint32_t fail;
	uint32_t skip;
	uint32_t total;
	bool valid;
};

static struct pnet_suite_summary g_last_suite_summary;

static bool parse_u32_arg(const char *s, uint32_t *out)
{
	char *endptr;
	unsigned long v;

	if (s == NULL || out == NULL) {
		return false;
	}

	v = strtoul(s, &endptr, 10);
	if (*s == '\0' || *endptr != '\0' || v > UINT32_MAX) {
		return false;
	}

	*out = (uint32_t)v;
	return true;
}

static void test_stats_reset(struct pnet_test_stats *s)
{
	s->pass = 0U;
	s->fail = 0U;
	s->last_err = 0;
	s->min_latency_ms = LLONG_MAX;
	s->max_latency_ms = 0;
	s->total_latency_ms = 0;
}

static void test_stats_add(struct pnet_test_stats *s, bool ok, int err, int64_t latency_ms)
{
	if (ok) {
		s->pass++;
		if (latency_ms < s->min_latency_ms) {
			s->min_latency_ms = latency_ms;
		}
		if (latency_ms > s->max_latency_ms) {
			s->max_latency_ms = latency_ms;
		}
		s->total_latency_ms += latency_ms;
	} else {
		s->fail++;
		s->last_err = err;
	}
}

static void test_stats_print(const struct shell *sh, const char *name, const struct pnet_test_stats *s)
{
	int64_t avg = 0;
	int64_t min = (s->pass > 0U) ? s->min_latency_ms : 0;

	if (s->pass > 0U) {
		avg = s->total_latency_ms / s->pass;
	}

	shell_print(sh,
			"TEST_RESULT,%s,pass=%u,fail=%u,last_err=%d,lat_ms_min=%lld,lat_ms_avg=%lld,lat_ms_max=%lld",
			name, s->pass, s->fail, s->last_err, min, avg, s->max_latency_ms);
}

static int pnet_tcp_close_if_open(void)
{
	if (tsock >= 0) {
		(void)zsock_close(tsock);
		tsock = -1;
	}

	return 0;
}

static int pnet_tcp_connect_internal(const char *ip, uint16_t port)
{
	struct timeval tv = {
		.tv_sec = 5,
		.tv_usec = 0,
	};
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
	};
	int rc;

	pnet_tcp_close_if_open();

	if (zsock_inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
		return -EINVAL;
	}

	tsock = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (tsock < 0) {
		return -errno;
	}

	(void)zsock_setsockopt(tsock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)zsock_setsockopt(tsock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	rc = zsock_connect(tsock, (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0) {
		rc = -errno;
		pnet_tcp_close_if_open();
		return rc;
	}

	return 0;
}

static int pnet_tcp_txrx_once(const char *payload)
{
	int tx;
	size_t plen = strlen(payload);

	tx = zsock_send(tsock, payload, plen, 0);
	if (tx < 0) {
		printk("test_tcp_loop tx failed: errno=%d\\n", errno);
		return -errno;
	}
	printk("test_tcp_loop tx bytes=%d payload='%s'\\n", tx, payload);
	/* Keep old send+recv behavior as reference.
	 * rcv = zsock_recv(tsock, rx, sizeof(rx) - 1, 0);
	 * if (rcv < 0) {
	 * 	printk("test_tcp_loop rx failed: errno=%d\\n", errno);
	 * 	return -errno;
	 * }
	 * rx[rcv] = '\0';
	 * printk("test_tcp_loop rx bytes=%d data='%s'\\n", rcv, rx);
	 */
	return 0;
}

static int pnet_ps_set_internal(bool enable)
{
	struct net_if *iface = net_if_get_default();
	struct wifi_ps_params params = { 0 };
	int rc;

	params.type = WIFI_PS_PARAM_STATE;
	params.enabled = enable ? WIFI_PS_ENABLED : WIFI_PS_DISABLED;
	rc = net_mgmt(NET_REQUEST_WIFI_PS, iface, &params, sizeof(params));
	if (rc) {
		return -EIO;
	}

	return 0;
}

static int pnet_ps_defaults_internal(void)
{
	struct net_if *iface = net_if_get_default();
	struct wifi_ps_params params = { 0 };

	params.listen_interval = 10;
	params.type = WIFI_PS_PARAM_LISTEN_INTERVAL;
	if (net_mgmt(NET_REQUEST_WIFI_PS, iface, &params, sizeof(params))) {
		return -EIO;
	}

	memset(&params, 0, sizeof(params));
	params.type = WIFI_PS_PARAM_WAKEUP_MODE;
	params.wakeup_mode = WIFI_PS_WAKEUP_MODE_LISTEN_INTERVAL;
	if (net_mgmt(NET_REQUEST_WIFI_PS, iface, &params, sizeof(params))) {
		return -EIO;
	}

	memset(&params, 0, sizeof(params));
	params.type = WIFI_PS_PARAM_TIMEOUT;
	params.timeout_ms = 3000;
	if (net_mgmt(NET_REQUEST_WIFI_PS, iface, &params, sizeof(params))) {
		return -EIO;
	}

	return 0;
}

static int cmd_tcp_connect(const struct shell *sh, size_t argc, char *argv[])
{
	uint32_t port;
	int rc;

	if (argc != 3) {
		shell_error(sh, "Invalid number of arguments\n");
		return 1;
	}
	if (!parse_u32_arg(argv[2], &port) || port == 0U || port > UINT16_MAX) {
		shell_error(sh, "Invalid port");
		return 1;
	}

	if (tsock > -1) {
		shell_error(sh, "Socket already connected");
		return 1;
	}

	printk("Connecting to %s:%s\n", argv[1], argv[2]);
	rc = pnet_tcp_connect_internal(argv[1], (uint16_t)port);
	if (rc) {
		shell_error(sh, "Failed to connect socket");
		return 1;
	}

	shell_print(sh, "TCP connect successful");

	return 0;
}

static int cmd_tcp_disconnect(const struct shell *sh, size_t argc, char *argv[])
{
	if (tsock < 0) {
		shell_error(sh, "Socket not connected");
		return 1;
	}

	zsock_close(tsock);
	tsock = -1;
	shell_print(sh, "TCP disconnect successful");

	return 0;
}

static int cmd_tcp_tx(const struct shell *sh, size_t argc, char *argv[])
{
	if (tsock < 0) {
		shell_error(sh, "Socket not connected");
		return 1;
	}

	int rc = zsock_send(tsock, argv[1], strlen(argv[1]), 0);
	if (rc < 0) {
		shell_error(sh, "Failed to send data");
		return 1;
	}
	shell_print(sh, "TCP send successful");

	return 0;
}

static int cmd_tcp_rx(const struct shell *sh, size_t argc, char *argv[])
{
	if (tsock < 0) {
		shell_error(sh, "Socket not connected");
		return 1;
	}

	char buf[1024];
	int rc = zsock_recv(tsock, buf, sizeof(buf) - 1, 0);
	if (rc < 0) {
		shell_error(sh, "Failed to receive data");
		return 1;
	}
	buf[rc] = 0;
	shell_print(sh, "TCP recv: %s", buf);

	return 0;
}

#ifdef CONFIG_DNS_RESOLVER
static void dns_resolve_cb(enum dns_resolve_status status,
			   struct dns_addrinfo *info, void *user_data)
{
	ARG_UNUSED(user_data);

	if (status == DNS_EAI_ALLDONE) {
		printk("DNS resolve complete\n");
		if (atomic_get(&g_dns_async_ctx.done) == 0) {
			g_dns_async_ctx.status = 0;
			atomic_set(&g_dns_async_ctx.done, 1);
			k_sem_give(&g_dns_async_ctx.done_sem);
		}

	} else if (status == DNS_EAI_INPROGRESS) {
		char hr_addr[NET_IPV4_ADDR_LEN];

		net_addr_ntop(info->ai_family, &net_sin(&info->ai_addr)->sin_addr,
			      hr_addr, sizeof(hr_addr));
		printk("A: %s\n", hr_addr);
	} else {
		printk("DNS resolve failed with status %d\n", status);
		if (atomic_get(&g_dns_async_ctx.done) == 0) {
			g_dns_async_ctx.status = status;
			atomic_set(&g_dns_async_ctx.done, 1);
			k_sem_give(&g_dns_async_ctx.done_sem);
		}
	}
}

static int resolv_async(const char *hostname)
{
	int rc = dns_get_addr_info(hostname,
			       DNS_QUERY_TYPE_A,
			       NULL,
			       dns_resolve_cb,
			       NULL,
			       MSEC_PER_SEC * 5);
	if (rc) {
		printk("DNS failed to resolve %s with %d: %s\n", hostname, rc, strerror(-rc));
		return 1;
	}
	printk("DNS query sent for %s\n", hostname);
	return 0;
}
#endif

static int resolv_sync(const char *hostname)
{
	struct zsock_addrinfo hints = { 0 };
	struct zsock_addrinfo *info;

	hints.ai_family = AF_INET;
	int ret = zsock_getaddrinfo(hostname, NULL, &hints, &info);
	if (ret) {
		printk("DNS failed to resolve %s with %d: %s\n", hostname, ret, strerror(-ret));
		return 1;
	}

	char hr_addr[NET_IPV4_ADDR_LEN];
	net_addr_ntop(info->ai_family, &net_sin(info->ai_addr)->sin_addr, hr_addr, sizeof(hr_addr));
	printk("A: %s\n", hr_addr);
	zsock_freeaddrinfo(info);
	return 0;
}

static int cmd_resolve(const struct shell *sh, size_t argc, char *argv[])
{
	if (argc == 2) {
	#ifdef CONFIG_DNS_RESOLVER
		return resolv_async(argv[1]);
	#else
		return resolv_sync(argv[1]);
	#endif
	}

	if (argc == 3) {
		if (strcmp(argv[2], "sync") == 0) {
			return resolv_sync(argv[1]);
		} else if (strcmp(argv[2], "async") == 0) {
	#ifdef CONFIG_DNS_RESOLVER
			return resolv_async(argv[1]);
	#else
			shell_error(sh, "Async DNS requires CONFIG_DNS_RESOLVER=y");
			return 1;
	#endif
		} else {
			shell_error(sh, "Invalid argument for method. Use 'sync' or 'async'");
			return 1;
		}
	}
	shell_error(sh, "Invalid number of arguments\n");
	return 1;
}

#ifdef CONFIG_DNS_RESOLVER
static int resolv_async_wait(const char *hostname, uint32_t timeout_ms)
{
	int rc;

	atomic_set(&g_dns_async_ctx.done, 0);
	g_dns_async_ctx.status = DNS_EAI_AGAIN;
	k_sem_reset(&g_dns_async_ctx.done_sem);

	rc = dns_get_addr_info(hostname,
			       DNS_QUERY_TYPE_A,
			       NULL,
			       dns_resolve_cb,
			       NULL,
			       timeout_ms);
	if (rc) {
		return 1;
	}

	if (k_sem_take(&g_dns_async_ctx.done_sem, K_MSEC(timeout_ms + 1000U)) != 0) {
		return 1;
	}

	return (g_dns_async_ctx.status == 0) ? 0 : 1;
}
#endif

static int cmd_connect(const struct shell *sh, size_t argc, char *argv[])
{
	int rc;
	struct wifi_connect_req_params params = { 0 };
	struct net_if *iface = net_if_get_default();

	// Old: required exactly 3 args (cmd + ssid + psk); now psk is optional for open networks
	if (argc < 2 || argc > 3) {
		shell_error(sh, "Usage: pnet connect <ssid> [psk]\n");
		return 1;
	}

	params.ssid = argv[1];
	params.ssid_length = strlen(argv[1]);
	params.channel = WIFI_CHANNEL_ANY;
	//params.security = WIFI_SECURITY_TYPE_PSK;
	// Security type set per-branch below depending on whether psk is provided
	params.band = WIFI_FREQ_BAND_UNKNOWN;
	//params.timeout = 12;

	/* Copy password only if provided; omit for open network connections */
	if (argc == 3) {
		params.psk = argv[2];
		params.psk_length = strlen(argv[2]);
		// WPA_AUTO_PERSONAL requires psk; use NONE for open networks (wifi_mgmt.c validates this)
		params.security = WIFI_SECURITY_TYPE_WPA_AUTO_PERSONAL;
		printk("Connecting to wifi %s with psk\n", params.ssid);
	} else {
		// Open network: WPA_AUTO_PERSONAL rejects empty psk with -EINVAL; must use NONE
		params.security = WIFI_SECURITY_TYPE_NONE;
		printk("Connecting to wifi %s (open network)\n", params.ssid);
	}

	rc = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface,
			(void *)&params, sizeof(params));
	if (rc) {
		printk("Connect request failed with %d\n", rc);
		return 0;
	}
	printk("Connect request sent\n");
	return 0;
}

/**
 * Parse BSSID from colon-separated hex format (AA:BB:CC:DD:EE:FF)
 * Returns 0 on success, -1 on error
 */
static int parse_bssid(const char *bssid_str, uint8_t *bssid_bytes)
{
	unsigned int a, b, c, d, e, f;
	
	if (bssid_str == NULL || bssid_bytes == NULL) {
		return -1;
	}
	
	/* Parse colon-separated hex format: AA:BB:CC:DD:EE:FF */
	if (sscanf(bssid_str, "%x:%x:%x:%x:%x:%x", &a, &b, &c, &d, &e, &f) != 6) {
		return -1;
	}
	
	/* Validate all values are 8-bit */
	if (a > 0xFF || b > 0xFF || c > 0xFF || d > 0xFF || e > 0xFF || f > 0xFF) {
		return -1;
	}
	
	bssid_bytes[0] = (uint8_t)a;
	bssid_bytes[1] = (uint8_t)b;
	bssid_bytes[2] = (uint8_t)c;
	bssid_bytes[3] = (uint8_t)d;
	bssid_bytes[4] = (uint8_t)e;
	bssid_bytes[5] = (uint8_t)f;
	
	return 0;
}

static int cmd_connect_bssid(const struct shell *sh, size_t argc, char *argv[])
{
	int rc;
	struct wifi_connect_req_params params = { 0 };
	struct net_if *iface = net_if_get_default();
	// Old: required exactly 4 args (cmd + ssid + psk + bssid); now psk is optional for open networks
	// Old usage: pnet connect_bssid <ssid> <psk> <bssid>
	// New usage: pnet connect_bssid <ssid> <bssid>          (open network)
	//            pnet connect_bssid <ssid> <psk> <bssid>    (secured network)
	if (argc < 3 || argc > 4) {
		shell_error(sh, "Usage: pnet connect_bssid <ssid> [psk] <bssid>\n");
		shell_error(sh, "  Open:    pnet connect_bssid <ssid> <AA:BB:CC:DD:EE:FF>\n");
		shell_error(sh, "  Secured: pnet connect_bssid <ssid> <psk> <AA:BB:CC:DD:EE:FF>\n");
		return 1;
	}

	params.ssid = argv[1];
	params.ssid_length = strlen(argv[1]);
	params.channel = WIFI_CHANNEL_ANY;
	//params.security = WIFI_SECURITY_TYPE_PSK;
	// Security type set per-branch below depending on whether psk is provided
	params.band = WIFI_FREQ_BAND_UNKNOWN;
	//params.timeout = 12;

	if (argc == 3) {
		/* Open network: connect_bssid <ssid> <bssid> */
		if (parse_bssid(argv[2], params.bssid) != 0) {
			shell_error(sh, "Invalid BSSID format. Use: AA:BB:CC:DD:EE:FF\n");
			return 1;
		}
		// Open network: WPA_AUTO_PERSONAL rejects empty psk with -EINVAL; must use NONE
		params.security = WIFI_SECURITY_TYPE_NONE;
		printk("Connecting to wifi %s (BSSID: %s, open network)\n", params.ssid, argv[2]);
	} else {
		/* Secured network: connect_bssid <ssid> <psk> <bssid> */
		if (parse_bssid(argv[3], params.bssid) != 0) {
			shell_error(sh, "Invalid BSSID format. Use: AA:BB:CC:DD:EE:FF\n");
			return 1;
		}
		params.psk = argv[2];
		params.psk_length = strlen(argv[2]);
		// WPA_AUTO_PERSONAL requires psk; use NONE for open networks (wifi_mgmt.c validates this)
		params.security = WIFI_SECURITY_TYPE_WPA_AUTO_PERSONAL;
		printk("Connecting to wifi %s (BSSID: %s) with psk\n", params.ssid, argv[3]);
	}

	rc = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface,
			(void *)&params, sizeof(params));
	if (rc) {
		printk("Connect request failed with %d\n", rc);
		return 0;
	}
	printk("Connect request sent\n");
	return 0;
}

static int cmd_wifi_psr(const struct shell *shell, size_t argc, char **argv)
{
	ARG_UNUSED(shell);
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (pnet_ps_defaults_internal() != 0) {
		printk("Wifi power save configs setup failed\n");
		return 1;
	}

	printk("Wifi power save configs setup done\n");
	return 0;
}

static int cmd_wifi_ps(const struct shell *shell, size_t argc, char **argv)
{
	struct net_if *iface = net_if_get_default();
	int enable = atoi(argv[1]);
	ARG_UNUSED(shell);
	ARG_UNUSED(argc);
	ARG_UNUSED(iface);

	printk("Setting wifi power save to %d\n", enable);
	// if (enable != 0) {
	// 	if (pnet_ps_defaults_internal() != 0) {
	// 		printk("Wifi power save configs setup failed\n");
	// 		return 1;
	// 	}
	// }
	
	if (pnet_ps_set_internal(enable != 0) != 0) {
		printk("WIFI_PS_PARAM_STATE failed\n");
		return 1;
	}

	printk("Done\n");
	return 0;
}

static int cmd_wifi_ps_li(const struct shell *shell, size_t argc, char **argv)
{
	struct net_if *iface = net_if_get_default();
	uint32_t val;
	ARG_UNUSED(shell);
	ARG_UNUSED(argc);

	if (!parse_u32_arg(argv[1], &val)) {
		printk("Invalid listen interval value\n");
		return 1;
	}

	struct wifi_ps_params params = { 0 };
	params.type = WIFI_PS_PARAM_LISTEN_INTERVAL;
	params.listen_interval = val;

	printk("Setting wifi power save listen interval to %u\n", val);
	if (net_mgmt(NET_REQUEST_WIFI_PS, iface, &params, sizeof(params))) {
		printk("WIFI_PS_PARAM_LISTEN_INTERVAL failed\n");
		return 1;
	}

	printk("Done\n");
	return 0;
}

static int cmd_test_tcp_loop(const struct shell *sh, size_t argc, char **argv)
{
	uint32_t port;
	uint32_t count;
	uint32_t interval_ms;
	uint32_t i;
	const char *payload = "PING";
	struct pnet_test_stats stats;
	// int64_t next_tx_ms;

	if (argc < 5 || argc > 6) {
		shell_error(sh,
			    "Usage: pnet test_tcp_loop <ip> <port> <count> <interval_ms> [payload]");
		return 1;
	}

	if (!parse_u32_arg(argv[2], &port) || !parse_u32_arg(argv[3], &count) ||
	    !parse_u32_arg(argv[4], &interval_ms) || port == 0U || port > UINT16_MAX ||
	    count == 0U) {
		shell_error(sh, "Invalid numeric arguments");
		return 1;
	}

	if (argc == 6) {
		payload = argv[5];
	}

	test_stats_reset(&stats);
	shell_print(sh, "TEST_START,TC-TCP-LOOP,count=%u", count);

	/* Keep old reconnect-at-start behavior as reference.
	 * pnet_tcp_close_if_open();
	 * connect_rc = pnet_tcp_connect_internal(argv[1], (uint16_t)port);
	 * if (connect_rc != 0) {
	 * 	test_stats_add(&stats, false, connect_rc, 0);
	 * 	test_stats_print(sh, "TC-TCP-LOOP", &stats);
	 * 	shell_print(sh, "TEST_END,TC-TCP-LOOP,result=FAIL");
	 * 	return 1;
	 * }
	 */
	if (tsock < 0) {
		shell_error(sh,
			    "Socket not connected. Use: pnet tcp_connect <ip> <port> before test_tcp_loop");
		return 1;
	}

	/* Keep old drift-compensated scheduler as reference. */
	// next_tx_ms = k_uptime_get();

	for (i = 0U; i < count; i++) {
		int rc;
		int64_t t0 = k_uptime_get();

		/* Keep old reconnect-per-iteration behavior as reference.
		 * rc = pnet_tcp_connect_internal(argv[1], (uint16_t)port);
		 * if (rc == 0) {
		 * 	rc = pnet_tcp_txrx_once(payload);
		 * }
		 * (void)pnet_tcp_close_if_open();
		 */
		rc = pnet_tcp_txrx_once(payload);

		if (rc == 0) {
			shell_print(sh, "TC-TCP-LOOP,iter=%u/%u,status=PASS", i + 1U, count);
			test_stats_add(&stats, true, 0, k_uptime_get() - t0);
		} else {
			shell_print(sh, "TC-TCP-LOOP,iter=%u/%u,status=FAIL,err=%d", i + 1U, count, rc);
			test_stats_add(&stats, false, rc, 0);
			break;
		}

		if (interval_ms > 0U && (i + 1U) < count) {
			/* Keep old fixed-delay behavior as reference. */
			// next_tx_ms += interval_ms;
			// int64_t now_ms = k_uptime_get();
			// if (next_tx_ms > now_ms) {
			// 	k_msleep((uint32_t)(next_tx_ms - now_ms));
			// } else {
			// 	next_tx_ms = now_ms;
			// }
			k_msleep(interval_ms);
		}
	}

	test_stats_print(sh, "TC-TCP-LOOP", &stats);
	shell_print(sh, "TEST_END,TC-TCP-LOOP,result=%s", (stats.fail == 0U) ? "PASS" : "FAIL");
	return (stats.fail == 0U) ? 0 : 1;
}

static int cmd_test_dns_loop(const struct shell *sh, size_t argc, char **argv)
{
	uint32_t count;
	uint32_t interval_ms;
	uint32_t i;
	struct pnet_test_stats stats;

	if (argc != 5) {
		shell_error(sh,
			    "Usage: pnet test_dns_loop <host> <sync|async|mixed> <count> <interval_ms>");
		return 1;
	}

	if (!parse_u32_arg(argv[3], &count) || !parse_u32_arg(argv[4], &interval_ms) ||
	    count == 0U) {
		shell_error(sh, "Invalid numeric arguments");
		return 1;
	}

	if (strcmp(argv[2], "sync") != 0 && strcmp(argv[2], "async") != 0 &&
	    strcmp(argv[2], "mixed") != 0) {
		shell_error(sh, "mode must be sync, async, or mixed");
		return 1;
	}

#ifndef CONFIG_DNS_RESOLVER
	if (strcmp(argv[2], "async") == 0 || strcmp(argv[2], "mixed") == 0) {
		shell_error(sh, "async and mixed DNS tests require CONFIG_DNS_RESOLVER=y");
		return 1;
	}
#endif

	test_stats_reset(&stats);
	shell_print(sh, "TEST_START,TC-DNS-LOOP,count=%u,mode=%s", count, argv[2]);

	for (i = 0U; i < count; i++) {
		int rc;
		int64_t t0 = k_uptime_get();

		if ((strcmp(argv[2], "sync") == 0) ||
		    (strcmp(argv[2], "mixed") == 0 && ((i % 2U) == 0U))) {
			rc = resolv_sync(argv[1]);
		} else {
			#if CONFIG_DNS_RESOLVER
			rc = resolv_async_wait(argv[1], 5000U);
			#endif
		}

		if (rc == 0) {
			test_stats_add(&stats, true, 0, k_uptime_get() - t0);
		} else {
			test_stats_add(&stats, false, rc, 0);
		}

		if (interval_ms > 0U) {
			k_msleep(interval_ms);
		}
	}

	test_stats_print(sh, "TC-DNS-LOOP", &stats);
	shell_print(sh, "TEST_END,TC-DNS-LOOP,result=%s", (stats.fail == 0U) ? "PASS" : "FAIL");
	return (stats.fail == 0U) ? 0 : 1;
}

static int cmd_test_ps_toggle(const struct shell *sh, size_t argc, char **argv)
{
	uint32_t count;
	uint32_t on_ms;
	uint32_t off_ms;
	uint32_t i;
	struct pnet_test_stats stats;

	if (argc != 4) {
		shell_error(sh, "Usage: pnet test_ps_toggle <count> <on_ms> <off_ms>");
		return 1;
	}

	if (!parse_u32_arg(argv[1], &count) || !parse_u32_arg(argv[2], &on_ms) ||
	    !parse_u32_arg(argv[3], &off_ms) || count == 0U) {
		shell_error(sh, "Invalid numeric arguments");
		return 1;
	}

	test_stats_reset(&stats);
	shell_print(sh, "TEST_START,TC-PS-TOGGLE,count=%u", count);

	if (pnet_ps_defaults_internal() != 0) {
		shell_error(sh, "Failed to program PS defaults");
		return 1;
	}

	for (i = 0U; i < count; i++) {
		int rc;
		int64_t t0 = k_uptime_get();

		rc = pnet_ps_set_internal(true);
		if (rc == 0 && on_ms > 0U) {
			k_msleep(on_ms);
		}
		if (rc == 0) {
			rc = pnet_ps_set_internal(false);
		}
		if (rc == 0 && off_ms > 0U) {
			k_msleep(off_ms);
		}

		if (rc == 0) {
			test_stats_add(&stats, true, 0, k_uptime_get() - t0);
		} else {
			test_stats_add(&stats, false, rc, 0);
		}
	}

	test_stats_print(sh, "TC-PS-TOGGLE", &stats);
	shell_print(sh, "TEST_END,TC-PS-TOGGLE,result=%s", (stats.fail == 0U) ? "PASS" : "FAIL");
	return (stats.fail == 0U) ? 0 : 1;
}

static int cmd_test_soak(const struct shell *sh, size_t argc, char **argv)
{
	uint32_t duration_s;
	uint32_t port;
	uint32_t interval_ms = 1000U;
	uint32_t iter = 0U;
	int64_t end_ms;
	struct pnet_test_stats tcp_stats;
	struct pnet_test_stats dns_stats;

	if (argc < 5 || argc > 6) {
		shell_error(sh,
			    "Usage: pnet test_soak <duration_s> <ip> <port> <host> [interval_ms]");
		return 1;
	}

	if (!parse_u32_arg(argv[1], &duration_s) || !parse_u32_arg(argv[3], &port) ||
	    port == 0U || port > UINT16_MAX) {
		shell_error(sh, "Invalid duration or port");
		return 1;
	}

	if (argc == 6 && !parse_u32_arg(argv[5], &interval_ms)) {
		shell_error(sh, "Invalid interval_ms");
		return 1;
	}

	test_stats_reset(&tcp_stats);
	test_stats_reset(&dns_stats);
	shell_print(sh, "TEST_START,TC-SOAK,duration_s=%u", duration_s);

	if (pnet_ps_defaults_internal() == 0) {
		(void)pnet_ps_set_internal(true);
	}

	end_ms = k_uptime_get() + ((int64_t)duration_s * 1000);
	while (k_uptime_get() < end_ms) {
		int rc;
		int64_t t0;

		t0 = k_uptime_get();
		rc = pnet_tcp_connect_internal(argv[2], (uint16_t)port);
		if (rc == 0) {
			rc = pnet_tcp_txrx_once("SOAK_PING");
		}
		(void)pnet_tcp_close_if_open();
		if (rc == 0) {
			test_stats_add(&tcp_stats, true, 0, k_uptime_get() - t0);
		} else {
			test_stats_add(&tcp_stats, false, rc, 0);
		}

		t0 = k_uptime_get();
		rc = resolv_sync(argv[4]);
		if (rc == 0) {
			test_stats_add(&dns_stats, true, 0, k_uptime_get() - t0);
		} else {
			test_stats_add(&dns_stats, false, rc, 0);
		}

		iter++;
		if ((iter % 10U) == 0U) {
			(void)pnet_ps_set_internal(false);
			k_msleep(200U);
			(void)pnet_ps_set_internal(true);
		}

		if (interval_ms > 0U) {
			k_msleep(interval_ms);
		}
	}

	(void)pnet_ps_set_internal(false);
	test_stats_print(sh, "TC-SOAK-TCP", &tcp_stats);
	test_stats_print(sh, "TC-SOAK-DNS", &dns_stats);
	shell_print(sh, "TEST_END,TC-SOAK,result=%s", (tcp_stats.fail == 0U && dns_stats.fail == 0U) ?
					       "PASS" : "FAIL");

	return (tcp_stats.fail == 0U && dns_stats.fail == 0U) ? 0 : 1;
}

static int run_tc005_ps_enable(const struct shell *sh)
{
	struct pnet_test_stats stats;
	int64_t t0 = k_uptime_get();
	int rc = 0;

	test_stats_reset(&stats);
	shell_print(sh, "TEST_START,TC-005");

	rc = pnet_ps_defaults_internal();
	if (rc == 0) {
		rc = pnet_ps_set_internal(true);
	}

	if (rc == 0) {
		test_stats_add(&stats, true, 0, k_uptime_get() - t0);
	} else {
		test_stats_add(&stats, false, rc, 0);
	}

	test_stats_print(sh, "TC-005", &stats);
	shell_print(sh, "TEST_END,TC-005,result=%s", (stats.fail == 0U) ? "PASS" : "FAIL");
	return (stats.fail == 0U) ? 0 : 1;
}

static int run_tc008_ps_idle_then_tx(const struct shell *sh, const char *ip, uint16_t port,
				     const char *payload, uint32_t idle_ms)
{
	struct pnet_test_stats stats;
	int64_t t0 = k_uptime_get();
	int rc;

	test_stats_reset(&stats);
	shell_print(sh, "TEST_START,TC-008,idle_ms=%u", idle_ms);

	rc = pnet_ps_defaults_internal();
	if (rc == 0) {
		rc = pnet_ps_set_internal(true);
	}
	if (rc == 0) {
		rc = pnet_tcp_connect_internal(ip, port);
	}
	if (rc == 0 && idle_ms > 0U) {
		k_msleep(idle_ms);
	}
	if (rc == 0) {
		rc = pnet_tcp_txrx_once(payload);
	}

	(void)pnet_tcp_close_if_open();
	(void)pnet_ps_set_internal(false);

	if (rc == 0) {
		test_stats_add(&stats, true, 0, k_uptime_get() - t0);
	} else {
		test_stats_add(&stats, false, rc, 0);
	}

	test_stats_print(sh, "TC-008", &stats);
	shell_print(sh, "TEST_END,TC-008,result=%s", (stats.fail == 0U) ? "PASS" : "FAIL");
	return (stats.fail == 0U) ? 0 : 1;
}

static int run_tc018_lite(const struct shell *sh, uint32_t duration_s, const char *ip,
			  uint16_t port, const char *host, uint32_t interval_ms)
{
	char duration_buf[16];
	char port_buf[8];
	char interval_buf[16];
	char *argv_local[6];

	snprintk(duration_buf, sizeof(duration_buf), "%u", duration_s);
	snprintk(port_buf, sizeof(port_buf), "%u", (uint32_t)port);
	snprintk(interval_buf, sizeof(interval_buf), "%u", interval_ms);

	argv_local[0] = "test_soak";
	argv_local[1] = duration_buf;
	argv_local[2] = (char *)ip;
	argv_local[3] = port_buf;
	argv_local[4] = (char *)host;
	argv_local[5] = interval_buf;

	return cmd_test_soak(sh, 6, argv_local);
}

static bool tc_is_supported(const char *tc_id)
{
	return (strcmp(tc_id, "TC-003") == 0) || (strcmp(tc_id, "TC-004") == 0) ||
	       (strcmp(tc_id, "TC-005") == 0) || (strcmp(tc_id, "TC-008") == 0) ||
	       (strcmp(tc_id, "TC-010") == 0) || (strcmp(tc_id, "TC-018") == 0);
}

static void suite_summary_reset(void)
{
	g_last_suite_summary.pass = 0U;
	g_last_suite_summary.fail = 0U;
	g_last_suite_summary.skip = 0U;
	g_last_suite_summary.total = 0U;
	g_last_suite_summary.valid = false;
}

static void suite_summary_add_result(bool pass)
{
	g_last_suite_summary.total++;
	if (pass) {
		g_last_suite_summary.pass++;
	} else {
		g_last_suite_summary.fail++;
	}
}

static void suite_summary_add_skip(uint32_t count)
{
	g_last_suite_summary.skip += count;
	g_last_suite_summary.total += count;
}

static void suite_summary_print_csv(const struct shell *sh)
{
	shell_print(sh,
			"TEST_SUITE_SUMMARY,pass=%u,fail=%u,skip=%u,total=%u,verdict=%s",
			g_last_suite_summary.pass, g_last_suite_summary.fail,
			g_last_suite_summary.skip, g_last_suite_summary.total,
			(g_last_suite_summary.fail == 0U) ? "PASS" : "FAIL");
}

static int cmd_test_run(const struct shell *sh, size_t argc, char **argv)
{
	uint32_t v;

	if (argc < 2) {
		shell_error(sh, "Usage: pnet test_run <TC-ID> [case-args]");
		return 1;
	}

	if (!tc_is_supported(argv[1])) {
		shell_print(sh,
			   "TEST_RESULT,%s,status=SKIP,reason=needs_external_or_fault_injection",
			   argv[1]);
		return 0;
	}

	if (strcmp(argv[1], "TC-003") == 0) {
		/* pnet test_run TC-003 <ip> <port> [count] [interval_ms] */
		char *args_local[6] = { "test_tcp_loop", NULL, NULL, "50", "100", "PING" };

		if (argc < 4) {
			shell_error(sh, "Usage: pnet test_run TC-003 <ip> <port> [count] [interval_ms]");
			return 1;
		}
		args_local[1] = argv[2];
		args_local[2] = argv[3];
		if (argc >= 5) {
			args_local[3] = argv[4];
		}
		if (argc >= 6) {
			args_local[4] = argv[5];
		}
		return cmd_test_tcp_loop(sh, 6, args_local);
	}

	if (strcmp(argv[1], "TC-004") == 0) {
		/* pnet test_run TC-004 <host> [sync|async|mixed] [count] [interval_ms] */
	#ifdef CONFIG_DNS_RESOLVER
		char *args_local[5] = { "test_dns_loop", NULL, "mixed", "20", "100" };
	#else
		char *args_local[5] = { "test_dns_loop", NULL, "sync", "20", "100" };
	#endif

		if (argc < 3) {
			shell_error(sh,
				    "Usage: pnet test_run TC-004 <host> [sync|async|mixed] [count] [interval_ms]");
			return 1;
		}
		args_local[1] = argv[2];
		if (argc >= 4) {
			args_local[2] = argv[3];
		}
		if (argc >= 5) {
			args_local[3] = argv[4];
		}
		if (argc >= 6) {
			args_local[4] = argv[5];
		}
		return cmd_test_dns_loop(sh, 5, args_local);
	}

	if (strcmp(argv[1], "TC-005") == 0) {
		return run_tc005_ps_enable(sh);
	}

	if (strcmp(argv[1], "TC-008") == 0) {
		/* pnet test_run TC-008 <ip> <port> [payload] [idle_ms] */
		const char *payload = "PING";
		uint32_t idle_ms = 1500U;

		if (argc < 4) {
			shell_error(sh, "Usage: pnet test_run TC-008 <ip> <port> [payload] [idle_ms]");
			return 1;
		}
		if (!parse_u32_arg(argv[3], &v) || v == 0U || v > UINT16_MAX) {
			shell_error(sh, "Invalid port");
			return 1;
		}
		if (argc >= 5) {
			payload = argv[4];
		}
		if (argc >= 6) {
			if (!parse_u32_arg(argv[5], &idle_ms)) {
				shell_error(sh, "Invalid idle_ms");
				return 1;
			}
		}
		return run_tc008_ps_idle_then_tx(sh, argv[2], (uint16_t)v, payload, idle_ms);
	}

	if (strcmp(argv[1], "TC-010") == 0) {
		/* pnet test_run TC-010 [count] [on_ms] [off_ms] */
		char *args_local[4] = { "test_ps_toggle", "30", "500", "500" };

		if (argc >= 3) {
			args_local[1] = argv[2];
		}
		if (argc >= 4) {
			args_local[2] = argv[3];
		}
		if (argc >= 5) {
			args_local[3] = argv[4];
		}
		return cmd_test_ps_toggle(sh, 4, args_local);
	}

	if (strcmp(argv[1], "TC-018") == 0) {
		/* pnet test_run TC-018 <duration_s> <ip> <port> <host> [interval_ms] */
		uint32_t duration_s = 300U;
		uint32_t interval_ms = 1000U;

		if (argc < 6) {
			shell_error(sh,
				    "Usage: pnet test_run TC-018 <duration_s> <ip> <port> <host> [interval_ms]");
			return 1;
		}
		if (!parse_u32_arg(argv[2], &duration_s) || !parse_u32_arg(argv[4], &v) ||
		    v == 0U || v > UINT16_MAX) {
			shell_error(sh, "Invalid duration or port");
			return 1;
		}
		if (argc >= 7) {
			if (!parse_u32_arg(argv[6], &interval_ms)) {
				shell_error(sh, "Invalid interval_ms");
				return 1;
			}
		}
		return run_tc018_lite(sh, duration_s, argv[3], (uint16_t)v, argv[5], interval_ms);
	}

	return 1;
}

static int cmd_test_run_all(const struct shell *sh, size_t argc, char **argv)
{
	int rc;
	char *tc003_args[6] = { "test_tcp_loop", NULL, NULL, "20", "100", "PING" };
	#ifdef CONFIG_DNS_RESOLVER
	char *tc004_args[5] = { "test_dns_loop", NULL, "mixed", "20", "100" };
	#else
	char *tc004_args[5] = { "test_dns_loop", NULL, "sync", "20", "100" };
	#endif
	char *tc010_args[4] = { "test_ps_toggle", "20", "300", "300" };

	/* pnet test_run_all <ip> <port> <host> [soak_duration_s] [soak_interval_ms] */
	uint32_t soak_duration_s = 180U;
	uint32_t soak_interval_ms = 1000U;
	uint32_t port;

	if (argc < 4) {
		shell_error(sh,
			    "Usage: pnet test_run_all <ip> <port> <host> [soak_duration_s] [soak_interval_ms]");
		return 1;
	}

	if (!parse_u32_arg(argv[2], &port) || port == 0U || port > UINT16_MAX) {
		shell_error(sh, "Invalid port");
		return 1;
	}
	if (argc >= 5 && !parse_u32_arg(argv[4], &soak_duration_s)) {
		shell_error(sh, "Invalid soak_duration_s");
		return 1;
	}
	if (argc >= 6 && !parse_u32_arg(argv[5], &soak_interval_ms)) {
		shell_error(sh, "Invalid soak_interval_ms");
		return 1;
	}

	shell_print(sh, "TEST_SUITE_START,PHASE1_TC_MAP");
	suite_summary_reset();

	tc003_args[1] = argv[1];
	tc003_args[2] = argv[2];
	rc = cmd_test_tcp_loop(sh, 6, tc003_args);
	suite_summary_add_result(rc == 0);

	tc004_args[1] = argv[3];
	rc = cmd_test_dns_loop(sh, 5, tc004_args);
	suite_summary_add_result(rc == 0);

	rc = run_tc005_ps_enable(sh);
	suite_summary_add_result(rc == 0);

	rc = run_tc008_ps_idle_then_tx(sh, argv[1], (uint16_t)port, "PING", 1500U);
	suite_summary_add_result(rc == 0);

	rc = cmd_test_ps_toggle(sh, 4, tc010_args);
	suite_summary_add_result(rc == 0);

	rc = run_tc018_lite(sh, soak_duration_s, argv[1], (uint16_t)port, argv[3], soak_interval_ms);
	suite_summary_add_result(rc == 0);

	shell_print(sh, "TEST_RESULT,TC-001,status=SKIP,reason=requires_event_orchestration");
	shell_print(sh, "TEST_RESULT,TC-002,status=SKIP,reason=covered_as_part_of_TC-003");
	shell_print(sh, "TEST_RESULT,TC-006,status=SKIP,reason=requires_precise_awake_state_control");
	shell_print(sh, "TEST_RESULT,TC-007,status=SKIP,reason=requires_precise_sleep_state_control");
	shell_print(sh, "TEST_RESULT,TC-009,status=SKIP,reason=requires_server_push_timing_control");
	shell_print(sh, "TEST_RESULT,TC-011,status=SKIP,reason=requires_fault_injection_hooks");
	shell_print(sh, "TEST_RESULT,TC-012,status=SKIP,reason=requires_fault_injection_hooks");
	shell_print(sh, "TEST_RESULT,TC-013,status=SKIP,reason=requires_external_AP_control");
	shell_print(sh, "TEST_RESULT,TC-014,status=SKIP,reason=requires_server_forced_close_or_reset");
	shell_print(sh, "TEST_RESULT,TC-015,status=SKIP,reason=needs_parallel_load_orchestration");
	shell_print(sh, "TEST_RESULT,TC-016,status=SKIP,reason=needs_parallel_command_orchestration");
	shell_print(sh, "TEST_RESULT,TC-017,status=SKIP,reason=needs_wifi_disconnect_orchestration");
	shell_print(sh, "TEST_RESULT,TC-019,status=SKIP,reason=needs_high_volume_server_harness");
	shell_print(sh, "TEST_RESULT,TC-020,status=SKIP,reason=needs_fault_cycle_harness");
	shell_print(sh, "TEST_RESULT,TC-021,status=SKIP,reason=manual_negative_or_additional_harness");
	shell_print(sh, "TEST_RESULT,TC-022,status=SKIP,reason=manual_negative_or_additional_harness");
	shell_print(sh, "TEST_RESULT,TC-023,status=SKIP,reason=manual_negative_or_additional_harness");
	suite_summary_add_skip(17U);
	g_last_suite_summary.valid = true;
	suite_summary_print_csv(sh);

	shell_print(sh, "TEST_SUITE_END,PHASE1_TC_MAP,result=%s",
		    (g_last_suite_summary.fail == 0U) ? "PASS" : "FAIL");
	return (g_last_suite_summary.fail == 0U) ? 0 : 1;
}

static int cmd_test_summary(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (!g_last_suite_summary.valid) {
		shell_error(sh, "No suite summary available. Run: pnet test_run_all ...");
		return 1;
	}

	suite_summary_print_csv(sh);
	return 0;
}

static int cmd_assert(const struct shell *shell, size_t argc, char **argv)
{
	printk("assert now!\n");
	__ASSERT(0, "pnet assert command");
	return 0;
}

/*enable macro to use wifi MAC read/write APIs*/
#if 0 
static void pnet_print_mac(const struct shell *sh, const char *label,
			   const uint8_t mac[WIFI_MAC_ADDR_LEN])
{
	char mac_str[sizeof("xx:xx:xx:xx:xx:xx")];

	shell_print(sh, "%s %s", label,
		    net_sprint_ll_addr_buf(mac, WIFI_MAC_ADDR_LEN, mac_str, sizeof(mac_str)));
}

static int pnet_parse_mac(const struct shell *sh, const char *mac_arg, uint8_t mac[WIFI_MAC_ADDR_LEN])
{
	if (net_bytes_from_str(mac, WIFI_MAC_ADDR_LEN, mac_arg) < 0) {
		shell_error(sh, "Invalid MAC address: %s", mac_arg);
		return -EINVAL;
	}

	return 0;
}

static int cmd_get_mac(const struct shell *sh, size_t argc, char **argv)
{
	uint8_t mac[WIFI_MAC_ADDR_LEN];
	int ret;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	ret = erpc_wifi_get_mac(mac);
	if (ret != 0) {
		shell_error(sh, "Effective MAC read failed (%d)", ret);
		return ret;
	}

	pnet_print_mac(sh, "Effective MAC:", mac);

	return 0;
}

static int cmd_otp_read_mac(const struct shell *sh, size_t argc, char **argv)
{
	uint8_t mac[WIFI_MAC_ADDR_LEN];
	int ret;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	ret = erpc_wifi_otp_mac_read(mac);
	if (ret != 0) {
		shell_error(sh, "OTP MAC read failed (%d)", ret);
		return ret;
	}

	pnet_print_mac(sh, "OTP MAC:", mac);

	return 0;
}

static int cmd_otp_write_mac(const struct shell *sh, size_t argc, char **argv)
{
	uint8_t mac[WIFI_MAC_ADDR_LEN];
	int ret;

	if (argc != 2) {
		shell_error(sh, "Usage: pnet otp_write_mac <aa:bb:cc:dd:ee:ff>");
		return -EINVAL;
	}

	ret = pnet_parse_mac(sh, argv[1], mac);
	if (ret != 0) {
		return ret;
	}

	ret = erpc_wifi_otp_mac_write(mac);
	if (ret != 0) {
		shell_error(sh, "OTP MAC write failed (%d). Check server [OTP] log for status.",
			    ret);
		return ret;
	}

	shell_print(sh, "OTP MAC write OK. Reboot WiFi module/server, then run pnet otp_read_mac.");

	return 0;
}
#endif

SHELL_STATIC_SUBCMD_SET_CREATE(pnet_subcmds,
		SHELL_CMD_ARG(init, NULL, "init wifi interface",
		  cmd_init, 0, 0),
/*enable macro to use wifi MAC read/write APIs*/
#if 0 
		SHELL_CMD(get_mac, NULL, "Read effective WiFi MAC (spoof/NVRAM/OTP/fallback)",
		 cmd_get_mac),
		SHELL_CMD(otp_read_mac, NULL, "Read raw OTP MAC from WiFi module",
		  cmd_otp_read_mac),
		SHELL_CMD_ARG(otp_write_mac, NULL, "Write OTP MAC <aa:bb:cc:dd:ee:ff>",
		  cmd_otp_write_mac, 2, 0),
#endif
		// Old: connect required psk (argc=3); now psk is optional (argc=2 or 3)
		SHELL_CMD_ARG(connect, NULL, "connect <ssid> [psk]",
		  cmd_connect, 2, 1),
		// Old: connect_bssid required psk (argc=4); now psk is optional (argc=3 or 4)
		SHELL_CMD_ARG(connect_bssid, NULL, "connect_bssid <ssid> [psk] <bssid>",
		  cmd_connect_bssid, 3, 1),
		SHELL_CMD_ARG(psr, NULL, "Enable PS at module",
		  cmd_wifi_psr, 0, 0),
		SHELL_CMD_ARG(ps, NULL, "Enable PS",
		  cmd_wifi_ps, 2, 0),
		SHELL_CMD_ARG(ps_li, NULL, "Set PS Listen Interval <value>",
		  cmd_wifi_ps_li, 2, 0),
		SHELL_CMD_ARG(tcp_connect, NULL, "tcp_connect <IP> <PORT>",
		  cmd_tcp_connect, 3, 0),
		SHELL_CMD_ARG(tcp_disconnect, NULL, "tcp_disconnect",
		  cmd_tcp_disconnect, 0, 0),
		SHELL_CMD_ARG(tcp_tx, NULL, "tcp_send <data>",
		  cmd_tcp_tx, 2, 0),
		SHELL_CMD_ARG(tcp_rx, NULL, "tcp rx",
		  cmd_tcp_rx, 0, 0),
		SHELL_CMD_ARG(resolve, NULL, "resolve <hostname> [method]",
		  cmd_resolve, 2, 1),
		SHELL_CMD_ARG(test_tcp_loop, NULL,
		  "test_tcp_loop <ip> <port> <count> <interval_ms> [payload]",
		  cmd_test_tcp_loop, 5, 1),
		SHELL_CMD_ARG(test_dns_loop, NULL,
		  "test_dns_loop <host> <sync|async|mixed> <count> <interval_ms>",
		  cmd_test_dns_loop, 5, 0),
		SHELL_CMD_ARG(test_ps_toggle, NULL,
		  "test_ps_toggle <count> <on_ms> <off_ms>",
		  cmd_test_ps_toggle, 4, 0),
		SHELL_CMD_ARG(test_soak, NULL,
		  "test_soak <duration_s> <ip> <port> <host> [interval_ms]",
		  cmd_test_soak, 5, 1),
		SHELL_CMD_ARG(test_run, NULL,
		  "test_run <TC-ID> [args]",
		  cmd_test_run, 2, 5),
		SHELL_CMD_ARG(test_run_all, NULL,
		  "test_run_all <ip> <port> <host> [soak_duration_s] [soak_interval_ms]",
		  cmd_test_run_all, 4, 2),
		SHELL_CMD_ARG(test_summary, NULL,
		  "print last suite summary CSV",
		  cmd_test_summary, 1, 0),
		SHELL_CMD_ARG(assert, NULL, "assert",
		  cmd_assert, 0, 0),
		  SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(pnet, &pnet_subcmds, "pnet commands", NULL);

#ifdef HAS_USB_ETH
static struct usbd_context *sample_usbd;

static int init_usb_eth(void)
{
	int err;

	printk("Initializing USB eth...\n");
	sample_usbd = sample_usbd_init_device(NULL);
	if (sample_usbd == NULL) {
		return -ENODEV;
	}

	err = usbd_enable(sample_usbd);
	if (err) {
		return err;
	}

	(void)net_config_init_app(NULL, "Initializing network");

	return 0;
}
#else
static int init_usb_eth(void)
{
	printk("USB eth not enabled\n");
	return -ENODEV;
}
#endif


static int usb_boot_init(void)
{
	init_usb_eth();
	return 0;
}

SYS_INIT(usb_boot_init, APPLICATION, 97);

static int pnet_test_init(void)
{
	#ifdef CONFIG_DNS_RESOLVER
	k_sem_init(&g_dns_async_ctx.done_sem, 0, 1);
	atomic_set(&g_dns_async_ctx.done, 0);
	g_dns_async_ctx.status = DNS_EAI_AGAIN;
	#endif
	return 0;
}

SYS_INIT(pnet_test_init, APPLICATION, 98);

#endif /* CONFIG_SHELL */
