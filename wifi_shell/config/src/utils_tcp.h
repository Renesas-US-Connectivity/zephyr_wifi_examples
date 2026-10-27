#ifndef _UTILS_TCP_H_
#define _UTILS_TCP_H_

typedef void (*tcp_rx_cb_t)(const char *data, int len);

void tcp_close(int sock);
int tcp_connect(tcp_rx_cb_t rx_cb, const char *server_ip, int port);

#endif /* _UTILS_TCP_H_ */