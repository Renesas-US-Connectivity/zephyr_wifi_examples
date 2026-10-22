#include <zephyr/net/dns_resolve.h>
#include <zephyr/net/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <zephyr/autoconf.h>

#include <sample_usbd.h>
#include <zephyr/net/net_config.h>
#include <zephyr/net/net_if.h>

static struct usbd_context *sample_usbd;

int init_usb_eth(void)
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
static int usb_boot_init(void)
{
	init_usb_eth();
	return 0;
}

SYS_INIT(usb_boot_init, APPLICATION, 255);
