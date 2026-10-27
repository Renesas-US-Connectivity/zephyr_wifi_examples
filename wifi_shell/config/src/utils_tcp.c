#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/http/client.h>
#include <zephyr/logging/log.h>
#include <fcntl.h>

#include "utils_iface.h"
#include "utils_tcp.h"

LOG_MODULE_REGISTER(util_tcp, LOG_LEVEL_INF);

static struct ctx {
	int sock;
	tcp_rx_cb_t rx_cb;
} ctx = { .sock = -1};

static bool sock_inuse(void)
{
	return ctx.sock >= 0;
}

int tcp_connect(tcp_rx_cb_t rx_cb, const char *server_ip, int port)
{
	int sock, ret;
	struct sockaddr_in sockaddr;

	if (sock_inuse()) {
		LOG_ERR("Socket is already in use");
		return -EBUSY;
	}

	memset(&ctx, 0, sizeof(ctx));
	ctx.sock = -1;

	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(port);
	ret = zsock_inet_pton(AF_INET, server_ip, &sockaddr.sin_addr.s_addr);
	if (ret < 0) {
		LOG_ERR("Invalid IP address (%s)", server_ip);
		return -EINVAL;
	}

	sock = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		LOG_ERR("Failed to create socket (%d/%d)", sock, errno);
		return -errno;
	}

	LOG_INF("Connect to [%s:%d]", server_ip, port);
	ret = zsock_connect(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
	if (ret < 0) {
		LOG_ERR("Failed to connect to %s:%u (%d)", server_ip, port, errno);
		goto out_close;
	}

	LOG_INF("Successfully connected to [%s:%d]", server_ip, port);
	ctx.rx_cb = rx_cb;

	int flags = zsock_fcntl(sock, F_GETFL, 0);
	flags |= O_NONBLOCK;
	zsock_fcntl(sock, F_SETFL, flags);
	ctx.sock = sock;
	return sock;

out_close:
	zsock_close(sock);
	return -errno;
}

void tcp_close(int sock)
{
	if (!sock_inuse() || ctx.sock != sock) {
		LOG_ERR("Socket is not in use or does not match the provided socket");
		return;
	}
	zsock_close(ctx.sock);
	memset(&ctx, 0, sizeof(ctx));
	ctx.sock = -1;
}

static void handle_rx(void)
{
	char buf[128];

	struct zsock_pollfd fds[1] = {0,};
	fds[0].fd = ctx.sock;
	fds[0].events = ZSOCK_POLLIN | ZSOCK_POLLERR | ZSOCK_POLLHUP;
	fds[0].revents = 0;

	int ret = zsock_poll(fds, 1, 1000);
	if (ret < 0) {
		LOG_ERR("Failed to poll socket (%d)", errno);
		return;
	}
	if (ret == 0) {
		return;
	}

	LOG_DBG("Sock [%d] Poll events: %08x", ctx.sock, fds[0].revents);

	if (fds[0].revents & ZSOCK_POLLERR) {
		LOG_ERR("Socket error -close sock");
		tcp_close(ctx.sock);
	} else if (fds[0].revents & ZSOCK_POLLHUP) {
		LOG_ERR("Socket hang up - close sock");
		tcp_close(ctx.sock);
	} else if (fds[0].revents & ZSOCK_POLLIN) {
		ssize_t received = zsock_recv(ctx.sock, buf, sizeof(buf), 0);
		if (received == -1 && errno == EAGAIN) {
			LOG_DBG("EAGAIN");
			return;
		}
		if (received < 0) {
			LOG_ERR("Failed to receive data (%d:%d) - close sock", received, errno);
			tcp_close(ctx.sock);
		}
		LOG_DBG("Sock [%d] RX [%d] data [%.*s]", ctx.sock, received, received, buf);
		if (ctx.rx_cb) {
			ctx.rx_cb(buf, received);
		}
	} else {
		LOG_WRN("Unexpected poll event: %08x", fds[0].revents);
		tcp_close(ctx.sock);
	}
}

static void tcp_thread(void *arg1, void *arg2, void *arg3)
{
	ARG_UNUSED(arg1);
	ARG_UNUSED(arg2);
	ARG_UNUSED(arg3);

	while (true) {
		if (!sock_inuse()) {
			k_sleep(K_SECONDS(1));
			continue;
		}
		handle_rx();
	}
}

K_THREAD_DEFINE(tcp_thread_id, 4096, tcp_thread, NULL, NULL, NULL,
		K_PRIO_PREEMPT(8), 0, 0);
