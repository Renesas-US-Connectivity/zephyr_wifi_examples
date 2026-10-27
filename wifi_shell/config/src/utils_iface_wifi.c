#include <assert.h>
#include <zephyr/logging/log.h>
#include "utils_iface.h"
#include "env_config.h"

LOG_MODULE_REGISTER(utils_iface, LOG_LEVEL_DBG);

static const int WIFI_PS_TIMEOUT_MS = 4000;
static const int WIFI_PS_LISTEN_INTERVAL = 10;

static struct ctx {
	struct net_mgmt_event_callback if_cb;
	struct net_mgmt_event_callback l3_cb;
	struct net_mgmt_event_callback l2_cb;
	struct k_event sync_evt;
	uint64_t connect_start;
	bool l2_connected;
	bool l3_connected;
	bool connected;

} ctx;

static void net_mgmt_callback(struct net_mgmt_event_callback *cb,
		uint64_t event, struct net_if *iface)
{
	(void)iface;

	switch (event) {
	case NET_EVENT_IF_UP:
		LOG_INF("NET_EVENT_IF_UP");
		break;
	case NET_EVENT_IF_DOWN:
		LOG_WRN("NET_EVENT_IF_DOWN");
		break;
	case NET_EVENT_IPV4_ADDR_ADD:
		LOG_DBG("NET_EVENT_IPV4_ADDR_ADD");
		//Allow DNS config
		k_sleep(K_MSEC(200));
		ctx.l3_connected = true;
		k_event_post(&ctx.sync_evt, 1);
		break;
	case NET_EVENT_WIFI_CONNECT_RESULT:
		const struct wifi_status *wstatus = (const struct wifi_status *)cb->info;

		LOG_DBG("NET_EVENT_WIFI_CONNECT_RESULT");
		if (wstatus->status == 0) {
			LOG_DBG("L2 connect after [%lld] ms", k_uptime_get() - ctx.connect_start);
			ctx.l2_connected = true;
		} else {
			LOG_WRN("NET_EVENT_WIFI_CONNECT_RESULT: status [%d] after [%lld] ms",
				wstatus->status, k_uptime_get() - ctx.connect_start);
			k_event_post(&ctx.sync_evt, 1);
		}
		break;
	case NET_EVENT_WIFI_DISCONNECT_RESULT:
		LOG_DBG("NET_EVENT_WIFI_DISCONNECT_RESULT");
		ctx.l2_connected = false;
		ctx.l3_connected = false;
		break;
	default:
		LOG_WRN("Unhandled network event 0x%llx", event);
		break;
	}
}

int iface_status(void)
{
	struct net_if *iface = net_if_get_default();
	int rc;
	struct wifi_iface_status iface_status = {};

	rc = net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, iface,
				&iface_status, sizeof(iface_status));
	if (rc) {
		LOG_ERR("Get status request failed rc=%d", rc);
		return -1;
	}

	LOG_INF("Interface status: channel=%u, rssi=%d BSSID=%02x:%02x:%02x:%02x:%02x:%02x",
			iface_status.channel,
			iface_status.rssi,
			iface_status.bssid[0], iface_status.bssid[1], iface_status.bssid[2],
			iface_status.bssid[3], iface_status.bssid[4], iface_status.bssid[5]);

	return 0;
}

int iface_connect(const char *ssid, const char *psk, int timeout_ms)
{
	struct net_if *iface = net_if_get_default();
	int rc;


	if (!ssid || !psk) {
		LOG_INF("Connecting with default ssid %s", ENV_SSID);
		ssid = ENV_SSID;
		psk = ENV_PSK;
	}
	struct wifi_connect_req_params params = {
		.ssid = ssid,
		.ssid_length = strlen(ssid),
		.psk = psk,
		.psk_length = strlen(psk),
		.security = WIFI_SECURITY_TYPE_PSK,
	};
	k_event_clear(&ctx.sync_evt, 1);
	LOG_INF("Connecting to SSID: %s", ssid);
	iface_ps_config();
	iface_ps(true);

	ctx.connect_start = k_uptime_get();
	rc = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface,
			(void *)&params, sizeof(params));
	if (rc) {
		LOG_ERR("Connect request failed with %d", rc);
		return -1;
	}

	LOG_INF("Waiting for network event");
	int events = k_event_wait(&ctx.sync_evt, 1, false, K_MSEC(timeout_ms));
	if (!(events & 1)) {
		LOG_ERR("Failed to connect within %d ms", timeout_ms);
		return -1;
	}

	if (ctx.l3_connected) {
		LOG_INF("L3 connected in %lld ms", k_uptime_get() - ctx.connect_start);
		return 0;
	} else {
		LOG_ERR("Failed to establish L3 connectivity");
		return -1;
	}
}

void iface_connect_if_needed(void)
{
	if (ctx.connected) {
		return;
	}
	iface_ensure_up();
	assert(iface_connect(NULL, NULL, 40000) == 0);
}

int iface_disconnect(void)
{
	struct net_if *iface = net_if_get_default();
	int rc;

	if (!iface) {
		LOG_ERR("No default network interface found");
		return -1;
	}

	rc = net_mgmt(NET_REQUEST_WIFI_DISCONNECT, iface, NULL, 0);
	if (rc) {
		LOG_ERR("Disconnect request failed with %d", rc);
		return -1;
	}
	ctx.connected = false;

	LOG_INF("Disconnect request sent");
	return 0;
}

void iface_ensure_up(void)
{
	struct net_if *iface = net_if_get_default();

	if (!iface) {
		LOG_ERR("No default network interface found");
		return;
	}
	if (net_if_is_up(iface)) {
		LOG_DBG("Network interface is already up");
		return;
	}
	net_if_up(iface);
	LOG_INF("Network interface brought up");
}

int iface_get_version(struct wifi_version *fw_version)
{
	struct net_if *iface = net_if_get_default();

	return net_mgmt(NET_REQUEST_WIFI_VERSION, iface,
				fw_version, sizeof(*fw_version));
}


int iface_up(void)
{
	struct net_if *iface = net_if_get_default();
	return net_if_up(iface);
}

int iface_down(void)
{
	struct net_if *iface = net_if_get_default();
	ctx.connected = false;
	return net_if_down(iface);
}

int iface_ps_config(void)
{
	struct net_if *iface = net_if_get_default();
	struct wifi_ps_params params = { 0 };

	LOG_INF("Config PS: listen_interval=[%d], timeout=[%d]", WIFI_PS_LISTEN_INTERVAL, WIFI_PS_TIMEOUT_MS);
	memset(&params, 0, sizeof(params));
	params.listen_interval = WIFI_PS_LISTEN_INTERVAL;
	params.type = WIFI_PS_PARAM_LISTEN_INTERVAL;

	if (net_mgmt(NET_REQUEST_WIFI_PS, iface, &params, sizeof(params))) {
		LOG_ERR("Failed to set listen interval");
		return -1;
	}

	memset(&params, 0, sizeof(params));
	params.type = WIFI_PS_PARAM_WAKEUP_MODE;
	params.wakeup_mode = WIFI_PS_WAKEUP_MODE_LISTEN_INTERVAL;

	if (net_mgmt(NET_REQUEST_WIFI_PS, iface, &params, sizeof(params))) {
		LOG_ERR("Failed to set PS wake up mode");
		return -1;
	}

	memset(&params, 0, sizeof(params));
	params.type = WIFI_PS_PARAM_TIMEOUT;
	params.timeout_ms = WIFI_PS_TIMEOUT_MS;
	if (net_mgmt(NET_REQUEST_WIFI_PS, iface, &params, sizeof(params))) {
		LOG_ERR("Failed to set PS timeout");
		return -1;
	}

	return 0;
}

int iface_ps(bool enable)
{
	struct net_if *iface = net_if_get_default();
	struct wifi_ps_params params = { 0 };

	LOG_INF("Set PS: enable=[%d]", enable);
	params.type = WIFI_PS_PARAM_STATE;
	params.enabled = enable ? WIFI_PS_ENABLED : WIFI_PS_DISABLED;
	if (net_mgmt(NET_REQUEST_WIFI_PS, iface, &params, sizeof(params))) {
		LOG_ERR("Failed to set WiFi power save state");
		return -1;
	}
	return 0;
}

#define L2_MGMT_EVENTS NET_EVENT_WIFI_CONNECT_RESULT | NET_EVENT_WIFI_DISCONNECT_RESULT
#define L3_MGMT_EVENTS NET_EVENT_IPV4_ADDR_ADD

#define NET_IF_EVENTS (NET_EVENT_IF_UP | NET_EVENT_IF_DOWN)


static int net_utils_init(void)
{
	LOG_INF("Initializing network utils");

	k_event_init(&ctx.sync_evt);

	net_mgmt_init_event_callback(&ctx.l2_cb, net_mgmt_callback, L2_MGMT_EVENTS);
	net_mgmt_add_event_callback(&ctx.l2_cb);
	net_mgmt_init_event_callback(&ctx.l3_cb, net_mgmt_callback, L3_MGMT_EVENTS);
	net_mgmt_add_event_callback(&ctx.l3_cb);
	net_mgmt_init_event_callback(&ctx.if_cb, net_mgmt_callback, NET_IF_EVENTS);
	net_mgmt_add_event_callback(&ctx.if_cb);
	return 0;
}

SYS_INIT(net_utils_init, POST_KERNEL, 50);