#ifndef UTILS_DNS_H
#define UTILS_DNS_H

#include <zephyr/net/net_ip.h>

int dns_resolve(const char *hostname, struct in_addr *results, size_t results_len);

#endif // UTILS_DNS_H
