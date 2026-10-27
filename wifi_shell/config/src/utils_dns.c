#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/dns_resolve.h>

LOG_MODULE_REGISTER(utils_dns, LOG_LEVEL_INF);

K_EVENT_DEFINE(dns_sync_evt);

static struct ctx {
	size_t results_cnt;
	size_t results_len;
	struct in_addr *results;
} ctx;

static void dns_resolve_cb(enum dns_resolve_status status, struct dns_addrinfo *info, void *user_data)
{
	if (status == DNS_EAI_ALLDONE) {
		LOG_DBG("DNS resolve complete\n");
		k_event_post(&dns_sync_evt, 1);

	} else if (status == DNS_EAI_INPROGRESS) {
		if (ctx.results_cnt < ctx.results_len) {
			ctx.results[ctx.results_cnt++] = net_sin(&info->ai_addr)->sin_addr;
		} else {
			LOG_DBG("Out of space for result (%d), drop", ctx.results_cnt);
		}
	} else {
		LOG_ERR("DNS resolve failed with status %d\n", status);
	}
}

int dns_resolve(const char *hostname, struct in_addr *results, size_t results_len)
{
	int ret;

	k_event_clear(&dns_sync_evt, 1);
	ctx.results = results;
	ctx.results_len = results_len;
	ctx.results_cnt = 0;
	ret = dns_get_addr_info(hostname,
			       DNS_QUERY_TYPE_A,
			       NULL,
			       dns_resolve_cb,
			       NULL,
			       MSEC_PER_SEC * 5);
	if (ret) {
		printk("DNS failed to resolve %s with %d: %s\n", hostname, ret, strerror(-ret));
		return -1;
	}

	ret = k_event_wait(&dns_sync_evt, 1, false, K_MSEC(MSEC_PER_SEC * 10));
	if (ret == 0) {
		printk("DNS resolve timed out\n");
		return -1;
	}

	if (ctx.results_cnt == 0) {
		return -1;
	}
	return ctx.results_cnt;
}
