
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
#include <zephyr/sys/reboot.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <zephyr/autoconf.h>

/* MQTT support merged from pnet_mqtt.c */
#include <zephyr/kernel.h>
#include <zephyr/net/mqtt.h>
#if defined(CONFIG_MQTT_LIB_TLS)
#include <zephyr/net/tls_credentials.h>
#include "ca_cert.h"
#endif

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

#define PNET_MAX_SOCKETS 4
static int tsocks[PNET_MAX_SOCKETS] = {-1, -1, -1, -1};

static int tsock = -1;
static int usock = -1;
static struct sockaddr_in g_udp_peer;  /* peer addr for sendto/recvfrom */

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

static int pnet_tcp_close_if_open(int id)
{
	if (id < 0 || id >= PNET_MAX_SOCKETS) {
		return -EINVAL;
	}

	if (tsocks[id] >= 0) {
		(void)zsock_close(tsocks[id]);
		tsocks[id] = -1;
	}

	return 0;
}

static int pnet_udp_close_if_open(void)
{
	if (usock >= 0) {
		(void)zsock_close(usock);
		usock = -1;
	}

	memset(&g_udp_peer, 0, sizeof(g_udp_peer));
	return 0;
}

static int pnet_tcp_connect_internal(int id, const char *ip, uint16_t port)
{
	if (id < 0 || id >= PNET_MAX_SOCKETS) {
		return -EINVAL;
	}

	struct timeval tv = {
		.tv_sec = 5,
		.tv_usec = 0,
	};
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
	};
	int rc;

	pnet_tcp_close_if_open(id);

	if (zsock_inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
		return -EINVAL;
	}

	tsocks[id] = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (tsocks[id] < 0) {
		return -errno;
	}

	(void)zsock_setsockopt(tsocks[id], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)zsock_setsockopt(tsocks[id], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	rc = zsock_connect(tsocks[id], (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0) {
		rc = -errno;
		pnet_tcp_close_if_open(id);
		return rc;
	}

	return 0;
}

static int pnet_udp_connect_internal(const char *ip, uint16_t remote_port, uint16_t local_port)
{
	struct timeval tv = {
		.tv_sec = 5,
		.tv_usec = 0,
	};
	struct sockaddr_in local_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(local_port), /* 0 = OS assigns ephemeral port */
		.sin_addr = { INADDR_ANY },
	};
	int rc;

	pnet_udp_close_if_open();

	memset(&g_udp_peer, 0, sizeof(g_udp_peer));
	g_udp_peer.sin_family = AF_INET;
	g_udp_peer.sin_port = htons(remote_port);

	if (zsock_inet_pton(AF_INET, ip, &g_udp_peer.sin_addr) != 1) {
		return -EINVAL;
	}

	usock = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (usock < 0) {
		return -errno;
	}

	/* Bind to local port — required by eRPC offload to assign a source
	 * port so the WiFi module can route outgoing frames correctly, and
	 * to receive incoming UDP datagrams sent to this port.
	 */
	rc = zsock_bind(usock, (struct sockaddr *)&local_addr, sizeof(local_addr));
	if (rc < 0) {
		rc = -errno;
		pnet_udp_close_if_open();
		return rc;
	}

	/* Set timeouts; ignore errors (offload may not support all options). */
	(void)zsock_setsockopt(usock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)zsock_setsockopt(usock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	return 0;
}

static int pnet_tcp_txrx_once(int id, const char *payload)
{
	if (id < 0 || id >= PNET_MAX_SOCKETS) {
		return -EINVAL;
	}

	int tx;
	size_t plen = strlen(payload);

	tx = zsock_send(tsocks[id], payload, plen, 0);
	if (tx < 0) {
		printk("test_tcp_loop tx failed: errno=%d\\n", errno);
		return -errno;
	}
	printk("test_tcp_loop tx bytes=%d payload='%s'\\n", tx, payload);
	/* Keep old send+recv behavior as reference.
	 * rcv = zsock_recv(tsocks[id], rx, sizeof(rx) - 1, 0);
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

	if (tsocks[0] > -1) {
		shell_error(sh, "Socket already connected");
		return 1;
	}

	printk("Connecting to %s:%s\n", argv[1], argv[2]);
	rc = pnet_tcp_connect_internal(0, argv[1], (uint16_t)port);
	if (rc) {
		shell_error(sh, "Failed to connect socket");
		return 1;
	}

	shell_print(sh, "TCP connect successful");

	return 0;
}

static int cmd_tcp_disconnect(const struct shell *sh, size_t argc, char *argv[])
{
	if (tsocks[0] < 0) {
		shell_error(sh, "Socket not connected");
		return 1;
	}

	pnet_tcp_close_if_open(0);
	shell_print(sh, "TCP disconnect successful");

	return 0;
}

static int cmd_udp_connect(const struct shell *sh, size_t argc, char *argv[])
{
	uint32_t remote_port;
	uint32_t local_port = 0U; /* 0 = let offload assign ephemeral port */
	int rc;

	if (argc < 3 || argc > 4) {
		shell_error(sh, "Usage: pnet udp_connect <remote_ip> <remote_port> [local_port]");
		return 1;
	}
	if (!parse_u32_arg(argv[2], &remote_port) || remote_port == 0U || remote_port > UINT16_MAX) {
		shell_error(sh, "Invalid remote port");
		return 1;
	}
	if (argc == 4) {
		if (!parse_u32_arg(argv[3], &local_port) || local_port > UINT16_MAX) {
			shell_error(sh, "Invalid local port");
			return 1;
		}
	}

	if (usock >= 0) {
		shell_error(sh, "UDP socket already open. Run pnet udp_disconnect first.");
		return 1;
	}

	printk("UDP peer %s:%u  local_port=%u\n", argv[1], remote_port, local_port);
	rc = pnet_udp_connect_internal(argv[1], (uint16_t)remote_port, (uint16_t)local_port);
	if (rc) {
		shell_error(sh, "Failed to open UDP socket (errno=%d)", -rc);
		return 1;
	}

	/* Print the actual local port assigned by the offload (important when
	 * local_port=0 was given and an ephemeral port was chosen). The remote
	 * peer must send UDP datagrams to this port for udp_rx to receive them.
	 */
	{
		struct sockaddr_in bound;
		socklen_t bound_len = sizeof(bound);

		if (zsock_getsockname(usock, (struct sockaddr *)&bound, &bound_len) == 0) {
			shell_print(sh, "UDP connect successful (local port: %u)",
				    ntohs(bound.sin_port));
		} else {
			shell_print(sh, "UDP connect successful");
		}
	}
	return 0;
}

static int cmd_udp_disconnect(const struct shell *sh, size_t argc, char *argv[])
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (usock < 0) {
		shell_error(sh, "UDP socket not connected");
		return 1;
	}

	zsock_close(usock);
	usock = -1;
	shell_print(sh, "UDP disconnect successful");

	return 0;
}

static int cmd_udp_tx(const struct shell *sh, size_t argc, char *argv[])
{
	int rc;

	if (argc != 2) {
		shell_error(sh, "Invalid number of arguments");
		return 1;
	}

	if (usock < 0) {
		shell_error(sh, "UDP socket not connected");
		return 1;
	}

	rc = zsock_sendto(usock, argv[1], strlen(argv[1]), 0,
			  (struct sockaddr *)&g_udp_peer, sizeof(g_udp_peer));
	if (rc < 0) {
		shell_error(sh, "Failed to send UDP data (errno=%d)", errno);
		return 1;
	}

	shell_print(sh, "UDP send successful");
	return 0;
}

static int cmd_udp_rx(const struct shell *sh, size_t argc, char *argv[])
{
	char buf[256];
	struct sockaddr_in from;
	socklen_t from_len;
	char src_str[NET_IPV4_ADDR_LEN];
	uint32_t timeout_ms = 5000U;
	struct timeval tv;
	int rc;

	if (usock < 0) {
		shell_error(sh, "UDP socket not connected");
		return 1;
	}

	if (argc >= 2) {
		if (!parse_u32_arg(argv[1], &timeout_ms) || timeout_ms == 0U) {
			shell_error(sh, "Usage: pnet udp_rx [timeout_ms]");
			return 1;
		}
	}

	/*
	 * Use zsock_poll() for the wall-clock timeout instead of SO_RCVTIMEO.
	 * The eRPC UDP offload driver silently ignores SO_RCVTIMEO on UDP
	 * sockets, causing recvfrom() to block indefinitely when no data
	 * arrives.  zsock_poll() is handled at the Zephyr network layer and
	 * reliably fires after the requested timeout regardless of the offload.
	 *
	 * If poll() reports POLLIN, the offload wake cycle may not yet be
	 * complete, so recvfrom(MSG_DONTWAIT) is retried a few times with a
	 * short back-off to avoid a false EAGAIN during the wake-up window.
	 */
	(void)tv; /* tv variable unused; kept to avoid compiler warning */

	shell_print(sh, "Waiting for UDP data (%u ms)...", timeout_ms);

	{
		struct zsock_pollfd pfd = {
			.fd = usock,
			.events = ZSOCK_POLLIN,
		};
		int poll_rc = zsock_poll(&pfd, 1, (int)timeout_ms);

		if (poll_rc == 0) {
			shell_print(sh, "UDP rx timeout — no data received in %u ms", timeout_ms);
			return 0;
		}
		if (poll_rc < 0) {
			shell_error(sh, "poll failed (errno=%d)", errno);
			return 1;
		}
	}

	/* Data reported ready — retry recvfrom with back-off to let the
	 * offload wake cycle finish before we read.
	 */
	from_len = sizeof(from);
	{
		int retry;

		rc = -1;
		for (retry = 0; retry < 5; retry++) {
			rc = zsock_recvfrom(usock, buf, sizeof(buf) - 1, ZSOCK_MSG_DONTWAIT,
					    (struct sockaddr *)&from, &from_len);
			if (rc >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
				break;
			}
			k_msleep(10);
		}
	}
	if (rc < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			shell_print(sh, "UDP rx timeout — no data received in %u ms", timeout_ms);
			return 0;
		}
		shell_error(sh, "recvfrom failed (errno=%d)", errno);
		return 1;
	}
	buf[rc] = '\0';

	net_addr_ntop(AF_INET, &from.sin_addr, src_str, sizeof(src_str));
	shell_print(sh, "UDP recv from %s:%u  len=%d  data: %s",
		    src_str, ntohs(from.sin_port), rc, buf);
	return 0;
}
static int cmd_tcp_tx(const struct shell *sh, size_t argc, char *argv[])
{
	if (tsocks[0] < 0) {
		shell_error(sh, "Socket not connected");
		return 1;
	}

	int rc = zsock_send(tsocks[0], argv[1], strlen(argv[1]), 0);
	if (rc < 0) {
		shell_error(sh, "Failed to send data");
		return 1;
	}
	shell_print(sh, "TCP send successful");

	return 0;
}

static int cmd_tcp_rx(const struct shell *sh, size_t argc, char *argv[])
{
	if (tsocks[0] < 0) {
		shell_error(sh, "Socket not connected");
		return 1;
	}

	char buf[1024];
	int rc = zsock_recv(tsocks[0], buf, sizeof(buf) - 1, 0);
	if (rc < 0) {
		shell_error(sh, "Failed to receive data");
		return 1;
	}
	buf[rc] = 0;
	shell_print(sh, "TCP recv: %s", buf);

	return 0;
}

static int cmd_tcp_connect_id(const struct shell *sh, size_t argc, char *argv[])
{
	uint32_t id, port;
	int rc;

	if (argc != 4) {
		shell_error(sh, "Usage: tcp_connect_id <id> <ip> <port>\n");
		return 1;
	}
	if (!parse_u32_arg(argv[1], &id) || id >= PNET_MAX_SOCKETS) {
		shell_error(sh, "Invalid id");
		return 1;
	}
	if (!parse_u32_arg(argv[3], &port) || port == 0U || port > UINT16_MAX) {
		shell_error(sh, "Invalid port");
		return 1;
	}

	if (tsocks[id] > -1) {
		shell_error(sh, "Socket already connected");
		return 1;
	}

	printk("Connecting to %s:%s on id %u\n", argv[2], argv[3], id);
	rc = pnet_tcp_connect_internal(id, argv[2], (uint16_t)port);
	if (rc) {
		shell_error(sh, "Failed to connect socket");
		return 1;
	}

	shell_print(sh, "TCP connect successful");

	return 0;
}

static int cmd_tcp_disconnect_id(const struct shell *sh, size_t argc, char *argv[])
{
	uint32_t id;

	if (argc != 2) {
		shell_error(sh, "Usage: tcp_disconnect_id <id>\n");
		return 1;
	}
	if (!parse_u32_arg(argv[1], &id) || id >= PNET_MAX_SOCKETS) {
		shell_error(sh, "Invalid id");
		return 1;
	}

	if (tsocks[id] < 0) {
		shell_error(sh, "Socket not connected");
		return 1;
	}

	pnet_tcp_close_if_open(id);
	shell_print(sh, "TCP disconnect successful");

	return 0;
}

static int cmd_tcp_tx_id(const struct shell *sh, size_t argc, char *argv[])
{
	uint32_t id;

	if (argc != 3) {
		shell_error(sh, "Usage: tcp_tx_id <id> <data>\n");
		return 1;
	}
	if (!parse_u32_arg(argv[1], &id) || id >= PNET_MAX_SOCKETS) {
		shell_error(sh, "Invalid id");
		return 1;
	}

	if (tsocks[id] < 0) {
		shell_error(sh, "Socket not connected");
		return 1;
	}

	int rc = zsock_send(tsocks[id], argv[2], strlen(argv[2]), 0);
	if (rc < 0) {
		shell_error(sh, "Failed to send data");
		return 1;
	}
	shell_print(sh, "TCP send successful");

	return 0;
}

static int cmd_tcp_rx_id(const struct shell *sh, size_t argc, char *argv[])
{
	uint32_t id;

	if (argc != 2) {
		shell_error(sh, "Usage: tcp_rx_id <id>\n");
		return 1;
	}
	if (!parse_u32_arg(argv[1], &id) || id >= PNET_MAX_SOCKETS) {
		shell_error(sh, "Invalid id");
		return 1;
	}

	if (tsocks[id] < 0) {
		shell_error(sh, "Socket not connected");
		return 1;
	}

	char buf[1024];
	int rc = zsock_recv(tsocks[id], buf, sizeof(buf) - 1, 0);
	if (rc < 0) {
		shell_error(sh, "Failed to receive data");
		return 1;
	}
	buf[rc] = 0;
	shell_print(sh, "TCP recv: %s", buf);

	return 0;
}

static int cmd_tcp_tx_loop_id(const struct shell *sh, size_t argc, char **argv)
{
	uint32_t id;
	uint32_t count;
	uint32_t interval_ms;
	uint32_t i;
	const char *payload = "PING";
	struct pnet_test_stats stats;

	if (argc < 4 || argc > 5) {
		shell_error(sh,
			    "Usage: pnet tcp_tx_loop_id <id> <count> <interval_ms> [payload]");
		return 1;
	}

	if (!parse_u32_arg(argv[1], &id) || id >= PNET_MAX_SOCKETS ||
	    !parse_u32_arg(argv[2], &count) || count == 0U ||
	    !parse_u32_arg(argv[3], &interval_ms)) {
		shell_error(sh, "Invalid arguments");
		return 1;
	}

	if (argc == 5) {
		payload = argv[4];
	}

	if (tsocks[id] < 0) {
		shell_error(sh,
			    "Socket id %u not connected. Use: pnet tcp_connect_id %u <ip> <port>",
			    id, id);
		return 1;
	}

	test_stats_reset(&stats);
	shell_print(sh, "TEST_START,TC-TCP-TX-LOOP-ID,id=%u,count=%u", id, count);

	for (i = 0U; i < count; i++) {
		int rc;
		int64_t t0 = k_uptime_get();

		rc = pnet_tcp_txrx_once((int)id, payload);
		if (rc == 0) {
			shell_print(sh,
				    "TC-TCP-TX-LOOP-ID,id=%u,iter=%u/%u,status=PASS",
				    id, i + 1U, count);
			test_stats_add(&stats, true, 0, k_uptime_get() - t0);
		} else {
			shell_print(sh,
				    "TC-TCP-TX-LOOP-ID,id=%u,iter=%u/%u,status=FAIL,err=%d",
				    id, i + 1U, count, rc);
			test_stats_add(&stats, false, rc, 0);
			break;
		}

		if (interval_ms > 0U && (i + 1U) < count) {
			k_msleep(interval_ms);
		}
	}

	test_stats_print(sh, "TC-TCP-TX-LOOP-ID", &stats);
	shell_print(sh, "TEST_END,TC-TCP-TX-LOOP-ID,id=%u,result=%s",
		    id, (stats.fail == 0U) ? "PASS" : "FAIL");

	return (stats.fail == 0U) ? 0 : 1;
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

/* ---------- MQTT merged functionality (from pnet_mqtt.c) ---------- */
#define PNET_MQTT_DEFAULT_BROKER_HOST "test.mosquitto.org"
#define PNET_MQTT_DEFAULT_BROKER_PORT 8883U
#define PNET_MQTT_DEFAULT_CLIENT_ID "pnet-shell-client"

#define PNET_MQTT_MAX_HOST_LEN 63
#define PNET_MQTT_MAX_CLIENT_ID_LEN 63

#define PNET_MQTT_IO_TIMEOUT_MS 30000
#define PNET_MQTT_WAKE_SETTLE_MS 300

static struct mqtt_client g_mqtt_client;
static struct sockaddr_storage g_mqtt_broker;
static uint8_t g_mqtt_rx_buf[1024];
static uint8_t g_mqtt_tx_buf[1024];

static bool g_mqtt_connected;
static bool g_mqtt_connack_received;
static bool g_mqtt_suback_received;
static bool g_mqtt_puback_received;
static uint16_t g_mqtt_puback_msg_id;
static int g_mqtt_last_evt_result;
static uint16_t g_mqtt_msg_id = 1U;
static bool g_in_dpm;

static bool g_mqtt_cfg_valid;
static char g_mqtt_broker_host[PNET_MQTT_MAX_HOST_LEN + 1];
static uint16_t g_mqtt_broker_port;
static char g_mqtt_client_id[PNET_MQTT_MAX_CLIENT_ID_LEN + 1];

static int pnet_mqtt_poll_once(int timeout_ms);
static int pnet_mqtt_parse_u32(const char *s, uint32_t *out);

static bool g_mqtt_thread_running = false;
static K_THREAD_STACK_DEFINE(pnet_mqtt_stack, 4096);
static struct k_thread pnet_mqtt_thread_data;
static k_tid_t pnet_mqtt_thread_id;

static void pnet_mqtt_thread(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	printk("MQTT background thread started\n");

	while (g_mqtt_thread_running && g_mqtt_connected) {
		int rc = pnet_mqtt_poll_once(1000);

		if (rc < 0 && rc != -EAGAIN && rc != -ETIMEDOUT) {
			printk("MQTT poll error: %d, connection may be lost\n", rc);
			break;
		}

		k_msleep(100);
	}

	g_mqtt_thread_running = false;
	printk("MQTT background thread stopped\n");
}

#if defined(CONFIG_MQTT_LIB_TLS)
#define PNET_MQTT_TLS_SEC_TAG 42
#define PNET_MQTT_TLS_PEER_VERIFY TLS_PEER_VERIFY_NONE
static sec_tag_t g_mqtt_sec_tags[] = { PNET_MQTT_TLS_SEC_TAG };
#endif

static void pnet_mqtt_wake_for_io(const char *reason)
{
	ARG_UNUSED(reason);
	if (g_in_dpm) {
		(void)pnet_ps_set_internal(false);
		k_msleep(PNET_MQTT_WAKE_SETTLE_MS);
	}
}

static void pnet_mqtt_back_to_dpm(void)
{
	if (g_mqtt_connected && g_in_dpm) {
		(void)pnet_ps_set_internal(true);
	}
}

static uint16_t pnet_mqtt_next_msg_id(void)
{
	g_mqtt_msg_id++;
	if (g_mqtt_msg_id == 0U) {
		g_mqtt_msg_id = 1U;
	}

	return g_mqtt_msg_id;
}

static int pnet_mqtt_parse_u32(const char *s, uint32_t *out)
{
	char *endptr;
	unsigned long v;

	if (s == NULL || out == NULL) {
		return -EINVAL;
	}

	v = strtoul(s, &endptr, 10);
	if (*s == '\0' || *endptr != '\0' || v > UINT32_MAX) {
		return -EINVAL;
	}

	*out = (uint32_t)v;
	return 0;
}

static void pnet_mqtt_cfg_set(const char *host, uint16_t port, const char *client_id)
{
	snprintk(g_mqtt_broker_host, sizeof(g_mqtt_broker_host), "%s", host);
	g_mqtt_broker_port = port;
	snprintk(g_mqtt_client_id, sizeof(g_mqtt_client_id), "%s", client_id);
	g_mqtt_cfg_valid = true;
}

static void pnet_mqtt_evt_handler(struct mqtt_client *const c, const struct mqtt_evt *evt)
{
	ARG_UNUSED(c);

	switch (evt->type) {
	case MQTT_EVT_CONNACK:
		g_mqtt_connack_received = true;
		g_mqtt_last_evt_result = evt->result;
		if (evt->result == 0) {
			g_mqtt_connected = true;
		}
		break;
	case MQTT_EVT_DISCONNECT:
		g_mqtt_connected = false;
		g_mqtt_connack_received = false;
		g_mqtt_suback_received = false;
		g_mqtt_puback_received = false;
		break;
	case MQTT_EVT_SUBACK:
		g_mqtt_suback_received = true;
		g_mqtt_last_evt_result = evt->result;
		break;
	case MQTT_EVT_PUBACK:
		g_mqtt_puback_received = true;
		g_mqtt_puback_msg_id = evt->param.puback.message_id;
		g_mqtt_last_evt_result = evt->result;
		break;
	case MQTT_EVT_PUBLISH: {
		const struct mqtt_publish_param *pub = &evt->param.publish;
		size_t remaining = pub->message.payload.len;
		uint8_t dump[64];

		printk("\nMQTT PUBLISH received on topic '%.*s' (len=%zu, QoS=%d):\n",
			   pub->message.topic.topic.size, pub->message.topic.topic.utf8,
			   pub->message.payload.len, pub->message.topic.qos);

		while (remaining > 0U) {
			int rd = mqtt_read_publish_payload_blocking(c, dump,
													   MIN(remaining, sizeof(dump) - 1));
			if (rd <= 0) {
				break;
			}
			dump[rd] = '\0';
			printk("%s", dump);
			remaining -= (size_t)rd;
		}
		printk("\n\n");

		if (pub->message.topic.qos == MQTT_QOS_1_AT_LEAST_ONCE) {
			(void)mqtt_publish_qos1_ack(c, &(struct mqtt_puback_param){ .message_id = pub->message_id });
		}
		break;
	}
	default:
		break;
	}
}

static int pnet_mqtt_resolve_broker(const char *host, uint16_t port,
					struct sockaddr_storage *out)
{
	struct sockaddr_in *broker4 = (struct sockaddr_in *)out;
	struct zsock_addrinfo hints = { 0 };
	struct zsock_addrinfo *res = NULL;
	char port_s[8];
	int rc;

	memset(out, 0, sizeof(*out));

	broker4->sin_family = AF_INET;
	broker4->sin_port = htons(port);
	if (zsock_inet_pton(AF_INET, host, &broker4->sin_addr) == 1) {
		return 0;
	}

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	snprintk(port_s, sizeof(port_s), "%u", (uint32_t)port);
	rc = zsock_getaddrinfo(host, port_s, &hints, &res);
	if (rc != 0 || res == NULL) {
		printk("zsock_getaddrinfo failed: rc=%d res=%p\n", rc, (void *)res);
		if (res != NULL) {
			zsock_freeaddrinfo(res);
		}
		return (rc != 0) ? -rc : -ENOENT;
	}

	memcpy(out, res->ai_addr, MIN((size_t)res->ai_addrlen, sizeof(*out)));
	zsock_freeaddrinfo(res);
	return 0;
}

static int pnet_mqtt_setup_client(const char *host, uint16_t port, const char *client_id)
{
	int rc;

	memset(&g_mqtt_client, 0, sizeof(g_mqtt_client));
	memset(&g_mqtt_broker, 0, sizeof(g_mqtt_broker));

	rc = pnet_mqtt_resolve_broker(host, port, &g_mqtt_broker);
	if (rc != 0) {
		return rc;
	}

	mqtt_client_init(&g_mqtt_client);
	g_mqtt_client.broker = &g_mqtt_broker;
	g_mqtt_client.evt_cb = pnet_mqtt_evt_handler;
	g_mqtt_client.client_id.utf8 = (uint8_t *)client_id;
	g_mqtt_client.client_id.size = strlen(client_id);
	g_mqtt_client.keepalive = 45;
	g_mqtt_client.protocol_version = MQTT_VERSION_3_1_1;
	g_mqtt_client.rx_buf = g_mqtt_rx_buf;
	g_mqtt_client.rx_buf_size = sizeof(g_mqtt_rx_buf);
	g_mqtt_client.tx_buf = g_mqtt_tx_buf;
	g_mqtt_client.tx_buf_size = sizeof(g_mqtt_tx_buf);

#if defined(CONFIG_MQTT_LIB_TLS)
	if (port == 8883U) {
		int tls_rc = tls_credential_add(PNET_MQTT_TLS_SEC_TAG,
						TLS_CREDENTIAL_CA_CERTIFICATE,
						ca_pem, ca_pem_len);
		if (tls_rc != 0 && tls_rc != -EEXIST) {
			g_mqtt_last_evt_result = tls_rc;
			return tls_rc;
		}

		tls_rc = tls_credential_add(PNET_MQTT_TLS_SEC_TAG,
						TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
						client_cert_pem, client_cert_pem_len);
		if (tls_rc != 0 && tls_rc != -EEXIST) {
			g_mqtt_last_evt_result = tls_rc;
			return tls_rc;
		}

		tls_rc = tls_credential_add(PNET_MQTT_TLS_SEC_TAG,
						TLS_CREDENTIAL_PRIVATE_KEY,
						/* old vars could be unavailable depending on cert header variant */
						// private_key_pem, private_key_pem_len);
						(const unsigned char *)PRIVATE_KEY, sizeof(PRIVATE_KEY));
		if (tls_rc != 0 && tls_rc != -EEXIST) {
			g_mqtt_last_evt_result = tls_rc;
			return tls_rc;
		}

		g_mqtt_client.transport.type = MQTT_TRANSPORT_SECURE;
		g_mqtt_client.transport.tls.config.peer_verify = PNET_MQTT_TLS_PEER_VERIFY;
		g_mqtt_client.transport.tls.config.cipher_count = 0;
		g_mqtt_client.transport.tls.config.cipher_list = NULL;
		g_mqtt_client.transport.tls.config.sec_tag_count =
			(PNET_MQTT_TLS_PEER_VERIFY == TLS_PEER_VERIFY_NONE) ? 0U : ARRAY_SIZE(g_mqtt_sec_tags);
		g_mqtt_client.transport.tls.config.sec_tag_list =
			(PNET_MQTT_TLS_PEER_VERIFY == TLS_PEER_VERIFY_NONE) ? NULL : g_mqtt_sec_tags;
		g_mqtt_client.transport.tls.config.cert_nocopy = 0;
	} else {
		g_mqtt_client.transport.type = MQTT_TRANSPORT_NON_SECURE;
	}
#else
	g_mqtt_client.transport.type = MQTT_TRANSPORT_NON_SECURE;
#endif

	return 0;
}

static int pnet_mqtt_disconnect_internal(void)
{
	int sock = -1;

	if (g_mqtt_thread_running) {
		g_mqtt_thread_running = false;
		k_thread_join(pnet_mqtt_thread_id, K_MSEC(2000));
	}

#if defined(CONFIG_MQTT_LIB_TLS)
	if (g_mqtt_client.transport.type == MQTT_TRANSPORT_SECURE) {
		sock = g_mqtt_client.transport.tls.sock;
	} else
#endif
	if (g_mqtt_client.transport.type == MQTT_TRANSPORT_NON_SECURE) {
		sock = g_mqtt_client.transport.tcp.sock;
	}

	if (sock >= 0) {
		(void)mqtt_disconnect(&g_mqtt_client, NULL);
		(void)zsock_close(sock);
	}

	g_mqtt_connected = false;
	g_mqtt_connack_received = false;
	g_mqtt_suback_received = false;
	g_mqtt_puback_received = false;
	g_mqtt_puback_msg_id = 0U;
	g_mqtt_last_evt_result = 0;
	memset(&g_mqtt_client, 0, sizeof(g_mqtt_client));

	return 0;
}

static int pnet_mqtt_poll_once(int timeout_ms)
{
	struct zsock_pollfd pfd;
	int rc;
	int sock;

#if defined(CONFIG_MQTT_LIB_TLS)
	if (g_mqtt_client.transport.type == MQTT_TRANSPORT_SECURE) {
		sock = g_mqtt_client.transport.tls.sock;
	} else
#endif
	if (g_mqtt_client.transport.type == MQTT_TRANSPORT_NON_SECURE) {
		sock = g_mqtt_client.transport.tcp.sock;
	} else {
		return -ENOTCONN;
	}

	if (sock < 0) {
		return -ENOTCONN;
	}

	pfd.fd = sock;
	pfd.events = ZSOCK_POLLIN;
	pfd.revents = 0;

	rc = zsock_poll(&pfd, 1, timeout_ms);
	if (rc < 0) {
		return -errno;
	}

	if (rc > 0 && (pfd.revents & ZSOCK_POLLIN) != 0) {
		rc = mqtt_input(&g_mqtt_client);
		if (rc == -EAGAIN || rc == 0) {
			return 0;
		}
		if (rc < 0) {
			return rc;
		}
	}

	if (g_mqtt_connected) {
		rc = mqtt_live(&g_mqtt_client);
		if (rc == -EAGAIN || rc == 0) {
			return 0;
		}
		return rc;
	}

	return 0;
}

static int pnet_mqtt_wait_for_flag(bool *flag, int timeout_ms)
{
	int64_t end = k_uptime_get() + timeout_ms;

	while (!(*flag) && k_uptime_get() < end) {
		int rc = pnet_mqtt_poll_once(200);
		if (rc < 0) {
			return rc;
		}
	}

	return *flag ? 0 : -ETIMEDOUT;
}

static int pnet_mqtt_connect_internal(const char *host, uint16_t port, const char *client_id)
{
	int rc;

	rc = pnet_mqtt_disconnect_internal();
	if (rc != 0) {
		return rc;
	}

	rc = pnet_mqtt_setup_client(host, port, client_id);
	if (rc != 0) {
		g_mqtt_last_evt_result = rc;
		return rc;
	}

	g_mqtt_connack_received = false;
	g_mqtt_last_evt_result = 0;

	rc = mqtt_connect(&g_mqtt_client);
	if (rc != 0) {
		g_mqtt_last_evt_result = rc;
		(void)pnet_mqtt_disconnect_internal();
		return rc;
	}

	rc = pnet_mqtt_wait_for_flag(&g_mqtt_connack_received, PNET_MQTT_IO_TIMEOUT_MS);
	if (rc != 0 || g_mqtt_last_evt_result != 0 || !g_mqtt_connected) {
		if (rc != 0 && g_mqtt_last_evt_result == 0) {
			g_mqtt_last_evt_result = rc;
		}
		(void)pnet_mqtt_disconnect_internal();
		return (rc != 0) ? rc : -EIO;
	}

	pnet_mqtt_cfg_set(host, port, client_id);

	g_mqtt_thread_running = true;
	pnet_mqtt_thread_id = k_thread_create(&pnet_mqtt_thread_data, pnet_mqtt_stack,
						K_THREAD_STACK_SIZEOF(pnet_mqtt_stack),
						pnet_mqtt_thread,
						NULL, NULL, NULL,
						K_PRIO_PREEMPT(7), 0, K_NO_WAIT);
	k_thread_name_set(pnet_mqtt_thread_id, "pnet_mqtt_poll");

	return 0;
}

static int pnet_mqtt_ensure_connected(void)
{
	if (g_mqtt_connected) {
		return 0;
	}

	if (!g_mqtt_cfg_valid) {
		return -ENOTCONN;
	}

	return pnet_mqtt_connect_internal(g_mqtt_broker_host, g_mqtt_broker_port, g_mqtt_client_id);
}

int cmd_mqtt_connect(const struct shell *sh, size_t argc, char *argv[])
{
	const char *host = PNET_MQTT_DEFAULT_BROKER_HOST;
	const char *client_id = PNET_MQTT_DEFAULT_CLIENT_ID;
	uint32_t port_u32 = PNET_MQTT_DEFAULT_BROKER_PORT;
	uint16_t port;
	int rc;

	if (argc > 1) {
		host = argv[1];
	}
	if (argc > 2) {
		rc = pnet_mqtt_parse_u32(argv[2], &port_u32);
		if (rc != 0) {
			shell_error(sh, "Invalid port");
			return 1;
		}
	}
	if (argc > 3) {
		client_id = argv[3];
	}
	if (argc > 4) {
		shell_error(sh, "Usage: pnet mqtt_connect [broker_host_or_ip] [port] [client_id]");
		return 1;
	}
	if (port_u32 == 0U || port_u32 > UINT16_MAX) {
		shell_error(sh, "Invalid port");
		return 1;
	}

	port = (uint16_t)port_u32;

	pnet_mqtt_wake_for_io("mqtt_connect");
	rc = pnet_mqtt_connect_internal(host, port, client_id);
	pnet_mqtt_back_to_dpm();

	if (rc != 0) {
		shell_error(sh, "MQTT connect failed (%d), detail=%d", rc, g_mqtt_last_evt_result);
		return 1;
	}

	shell_print(sh, "MQTT connect successful: %s:%u", host, (uint32_t)port);
	return 0;
}

int cmd_mqtt_publish(const struct shell *sh, size_t argc, char *argv[])
{
	struct mqtt_publish_param param = { 0 };
	enum mqtt_qos qos = MQTT_QOS_0_AT_MOST_ONCE;
	uint32_t qos_u32 = 0U;
	uint16_t msg_id;
	int rc;

	if (argc < 3 || argc > 4) {
		shell_error(sh, "Usage: pnet mqtt_publish <topic> <payload> [qos:0|1]");
		return 1;
	}
	if (argc == 4) {
		rc = pnet_mqtt_parse_u32(argv[3], &qos_u32);
		if (rc != 0 || qos_u32 > 1U) {
			shell_error(sh, "Invalid qos, use 0 or 1");
			return 1;
		}
		qos = (qos_u32 == 0U) ? MQTT_QOS_0_AT_MOST_ONCE : MQTT_QOS_1_AT_LEAST_ONCE;
	}

	pnet_mqtt_wake_for_io("mqtt_publish");

	rc = pnet_mqtt_ensure_connected();
	if (rc != 0) {
		shell_error(sh, "MQTT not connected (%d)", rc);
		pnet_mqtt_back_to_dpm();
		return 1;
	}

	msg_id = pnet_mqtt_next_msg_id();
	param.message.topic.qos = qos;
	param.message.topic.topic.utf8 = (uint8_t *)argv[1];
	param.message.topic.topic.size = strlen(argv[1]);
	param.message.payload.data = (uint8_t *)argv[2];
	param.message.payload.len = strlen(argv[2]);
	param.message_id = msg_id;
	param.dup_flag = 0U;
	param.retain_flag = 0U;

	g_mqtt_puback_received = false;
	g_mqtt_puback_msg_id = 0U;
	g_mqtt_last_evt_result = 0;

	rc = mqtt_publish(&g_mqtt_client, &param);
	if (rc != 0) {
		shell_error(sh, "mqtt_publish failed (%d)", rc);
		pnet_mqtt_back_to_dpm();
		return 1;
	}

	if (qos == MQTT_QOS_1_AT_LEAST_ONCE) {
		rc = pnet_mqtt_wait_for_flag(&g_mqtt_puback_received, PNET_MQTT_IO_TIMEOUT_MS);
		if (rc != 0 || g_mqtt_last_evt_result != 0 || g_mqtt_puback_msg_id != msg_id) {
			shell_error(sh, "MQTT PUBACK failed (%d, evt=%d)", rc, g_mqtt_last_evt_result);
			pnet_mqtt_back_to_dpm();
			return 1;
		}
	} else {
		(void)pnet_mqtt_poll_once(100);
	}

	shell_print(sh, "MQTT publish successful: topic=%s qos=%u", argv[1],
			(qos == MQTT_QOS_0_AT_MOST_ONCE) ? 0U : 1U);
	pnet_mqtt_back_to_dpm();
	return 0;
}

int cmd_mqtt_subscribe(const struct shell *sh, size_t argc, char *argv[])
{
	struct mqtt_topic topic = { 0 };
	struct mqtt_subscription_list sub_list = { 0 };
	enum mqtt_qos qos = MQTT_QOS_1_AT_LEAST_ONCE;
	uint32_t qos_u32 = 1U;
	int rc;

	if (argc < 2 || argc > 3) {
		shell_error(sh, "Usage: pnet mqtt_subscribe <topic> [qos:0|1]");
		return 1;
	}
	if (argc == 3) {
		rc = pnet_mqtt_parse_u32(argv[2], &qos_u32);
		if (rc != 0 || qos_u32 > 1U) {
			shell_error(sh, "Invalid qos, use 0 or 1");
			return 1;
		}
		qos = (qos_u32 == 0U) ? MQTT_QOS_0_AT_MOST_ONCE : MQTT_QOS_1_AT_LEAST_ONCE;
	}

	pnet_mqtt_wake_for_io("mqtt_subscribe");

	rc = pnet_mqtt_ensure_connected();
	if (rc != 0) {
		shell_error(sh, "MQTT not connected (%d)", rc);
		pnet_mqtt_back_to_dpm();
		return 1;
	}

	topic.topic.utf8 = (uint8_t *)argv[1];
	topic.topic.size = strlen(argv[1]);
	topic.qos = qos;

	sub_list.list = &topic;
	sub_list.list_count = 1U;
	sub_list.message_id = pnet_mqtt_next_msg_id();

	g_mqtt_suback_received = false;
	g_mqtt_last_evt_result = 0;

	rc = mqtt_subscribe(&g_mqtt_client, &sub_list);
	if (rc != 0) {
		shell_error(sh, "mqtt_subscribe failed (%d)", rc);
		pnet_mqtt_back_to_dpm();
		return 1;
	}

	rc = pnet_mqtt_wait_for_flag(&g_mqtt_suback_received, PNET_MQTT_IO_TIMEOUT_MS);
	if (rc != 0 || g_mqtt_last_evt_result != 0) {
		shell_error(sh, "MQTT SUBACK failed (%d, evt=%d)", rc, g_mqtt_last_evt_result);
		pnet_mqtt_back_to_dpm();
		return 1;
	}

	shell_print(sh, "MQTT subscribe successful: topic=%s qos=%u", argv[1],
			(qos == MQTT_QOS_0_AT_MOST_ONCE) ? 0U : 1U);
	pnet_mqtt_back_to_dpm();
	return 0;
}

int cmd_mqtt_disconnect(const struct shell *sh, size_t argc, char *argv[])
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	pnet_mqtt_wake_for_io("mqtt_disconnect");
	(void)pnet_mqtt_disconnect_internal();
	(void)pnet_ps_set_internal(true);
	shell_print(sh, "MQTT disconnect successful");
	g_in_dpm = true;
	return 0;
}

/* ---------- end MQTT merged functionality ---------- */
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
	if (tsocks[0] < 0) {
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
		 * rc = pnet_tcp_connect_internal(0, argv[1], (uint16_t)port);
		 * if (rc == 0) {
		 * 	rc = pnet_tcp_txrx_once(0, payload);
		 * }
		 * (void)pnet_tcp_close_if_open(0);
		 */
		rc = pnet_tcp_txrx_once(0, payload);

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
		rc = pnet_tcp_connect_internal(0, argv[2], (uint16_t)port);
		if (rc == 0) {
			rc = pnet_tcp_txrx_once(0, "SOAK_PING");
		}
		(void)pnet_tcp_close_if_open(0);
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
		rc = pnet_tcp_connect_internal(0, ip, port);
	}
	if (rc == 0 && idle_ms > 0U) {
		k_msleep(idle_ms);
	}
	if (rc == 0) {
		rc = pnet_tcp_txrx_once(0, payload);
	}

	(void)pnet_tcp_close_if_open(0);
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

static int cmd_reset(const struct shell *shell, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	shell_print(shell, "Rebooting host...");
	sys_reboot(SYS_REBOOT_COLD);
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
		SHELL_CMD_ARG(udp_connect, NULL, "udp_connect <remote_ip> <remote_port>",
		  cmd_udp_connect, 3, 0),
		SHELL_CMD_ARG(udp_disconnect, NULL, "udp_disconnect",
		  cmd_udp_disconnect, 0, 0),
		SHELL_CMD_ARG(udp_tx, NULL, "udp_send <data>",
		  cmd_udp_tx, 2, 0),
		SHELL_CMD_ARG(udp_rx, NULL, "udp_rx [timeout_ms]",
		  cmd_udp_rx, 1, 1),
		SHELL_CMD_ARG(tcp_connect_id, NULL, "tcp_connect_id <id> <IP> <PORT>",
		  cmd_tcp_connect_id, 4, 0),
		SHELL_CMD_ARG(tcp_disconnect_id, NULL, "tcp_disconnect_id <id>",
		  cmd_tcp_disconnect_id, 2, 0),
		SHELL_CMD_ARG(tcp_tx_id, NULL, "tcp_tx_id <id> <data>",
		  cmd_tcp_tx_id, 3, 0),
		SHELL_CMD_ARG(tcp_tx_loop_id, NULL,
		  "tcp_tx_loop_id <id> <count> <interval_ms> [payload]",
		  cmd_tcp_tx_loop_id, 4, 1),
		SHELL_CMD_ARG(tcp_rx_id, NULL, "tcp_rx_id <id>",
		  cmd_tcp_rx_id, 2, 0),
		SHELL_CMD_ARG(resolve, NULL, "resolve <hostname> [method]",
		  cmd_resolve, 2, 1),
        SHELL_CMD_ARG(mqtt_connect, NULL,
		  "mqtt_connect [broker_host_or_ip] [port] [client_id]",
		  cmd_mqtt_connect, 1, 3),
		SHELL_CMD_ARG(mqtt_publish, NULL,
		  "mqtt_publish <topic> <payload> [qos:0|1]",
		  cmd_mqtt_publish, 3, 1),
		SHELL_CMD_ARG(mqtt_subscribe, NULL,
		  "mqtt_subscribe <topic> [qos:0|1]",
		  cmd_mqtt_subscribe, 2, 1),
		SHELL_CMD_ARG(mqtt_disconnect, NULL,
		  "mqtt_disconnect",
		  cmd_mqtt_disconnect, 1, 0),
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
		SHELL_CMD_ARG(reset, NULL, "reset/reboot host",
		  cmd_reset, 0, 0),
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
