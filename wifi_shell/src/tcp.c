#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/http/client.h>
#include <zephyr/logging/log.h>
#include <fcntl.h>

#include "utils_iface.h"
#include "utils_tcp.h"
#include "env_config.h"

LOG_MODULE_REGISTER(tcp, LOG_LEVEL_DBG);

static const char *echo_payload ="HELLO";

static struct ctx {
	int sock;
	int echo_interval_s;
	int64_t last_echo_tx;
} ctx = { .sock = -1 };

static int cmd_tcp_close(const struct shell *shell, size_t argc, char **argv)
{
	if (ctx.sock >= 0) {
		tcp_close(ctx.sock);
	}
	ctx.sock = -1;
	return 0;
}

static int connect_common(const struct shell *shell, size_t argc, char **argv, tcp_rx_cb_t rx_cb)
{
	const char *host;
	int port;

	if (ctx.sock != -1) {
		shell_error(shell, "TCP connection already established");
		return -EALREADY;
	}

	if (argc == 1) {
		shell_print(shell, "Using default echo server");
		host = ENV_ECHO_SERVER_IP;
		port = ENV_ECHO_SERVER_PORT;
	} else if (argc >= 3) {
		host = argv[1];
		port = atoi(argv[2]);
	}
	else {
		shell_error(shell, "Invalid arguments");
		return -EINVAL;
	}

	ctx.sock = tcp_connect(rx_cb, host, port);
	return ctx.sock;
}

static void generic_rx(const char *data, int len)
{
	LOG_INF("Generic RX data [%.*s]", len, data);
}

static int cmd_tcp_connect(const struct shell *shell, size_t argc, char **argv)
{
	connect_common(shell, argc, argv, generic_rx);
	return 0;
}

static void echo_tx_handler(struct k_work *work);
K_WORK_DELAYABLE_DEFINE(echo_tx_work, echo_tx_handler);

static void echo_rx(const char *data, int len)
{
	int64_t now = k_uptime_get();
	int64_t rtt = now - ctx.last_echo_tx;
	LOG_INF("Echo RTT: %" PRId64 " ms", rtt);
	LOG_INF("Echo RX data [%.*s]", len, data);
}

static void echo_tx_handler(struct k_work *work)
{
	if (ctx.sock == -1) {
		return;
	}
	ctx.last_echo_tx = k_uptime_get();
	k_work_schedule(&echo_tx_work, K_SECONDS(ctx.echo_interval_s));
	zsock_send(ctx.sock, echo_payload, strlen(echo_payload), 0);
}

static int cmd_tcp_connect_echo(const struct shell *shell, size_t argc, char **argv)
{
	int interval;

	if (argc == 1) {
		interval = ENV_ECHO_INTERVAL_S;
	} else if (argc == 4) {
		interval = atoi(argv[3]);
	} else {
		shell_error(shell, "Invalid arguments");
		return -EINVAL;
	}

	connect_common(shell, argc, argv, echo_rx);

	ctx.echo_interval_s = interval;
	shell_print(shell, "Echo every %d seconds", ctx.echo_interval_s);
	k_work_schedule(&echo_tx_work, K_SECONDS(1));
	return 0;
}

static int cmd_tcp_tx(const struct shell *shell, size_t argc, char **argv)
{
	if (ctx.sock == -1) {
		shell_error(shell, "No active TCP connection");
		return -ENOTCONN;
	}

	const char *data = argv[1];
	int len = strlen(data);
	int ret = zsock_send(ctx.sock, data, len, 0);
	if (ret < 0) {
		shell_error(shell, "Failed to send data (%d)", errno);
		return -errno;
	}

	shell_print(shell, "Sent %d bytes", ret);
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(tcp_subcmds,
		SHELL_CMD_ARG(connect_echo, NULL, "Connect to server <host> <port> and echo at interval",
			cmd_tcp_connect_echo, 1, 3),
		SHELL_CMD_ARG(connect, NULL, "Connect to server <host> <port>",
			cmd_tcp_connect, 1, 2),
		SHELL_CMD_ARG(tx, NULL, "Send some data",
			cmd_tcp_tx, 2, 0),
		SHELL_CMD_ARG(close, NULL, "Close the current TCP connection",
			cmd_tcp_close, 1, 0),
		SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(tcp, &tcp_subcmds,
	"tcp commands", NULL);
