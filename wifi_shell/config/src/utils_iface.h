#ifndef UTILS_IFACE_H
#define UTILS_IFACE_H

#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/net_if.h>
#include <zephyr/device.h>


int iface_connect(const char *ssid, const char *psk, int timeout_ms);
void iface_connect_if_needed(void);
int iface_disconnect(void);
int iface_status(void);
int iface_ps_config(void);
int iface_ps(bool enable);
void iface_ensure_up(void);
int iface_get_version(struct wifi_version *fw_version);

int iface_up(void);
int iface_down(void);

#endif // UTILS_IFACE_H
