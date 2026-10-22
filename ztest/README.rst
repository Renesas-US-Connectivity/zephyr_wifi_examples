Overview
********

**ztest** is a Zephyr-based Wi-Fi integration test application for the Renesas
eRPC Wi-Fi driver. It exercises interface lifecycle operations, DNS resolution,
and authenticated HTTPS requests using Zephyr's ztest framework.


Test Coverage
=============

The ``net_tests`` suite is implemented in ``src/tests_iface.c``:

- ``test_version``: bring the interface up, retrieve the driver version, and
  bring the interface down, repeated five times.
- ``test_dns``: connect to the configured access point, resolve ``www.sunet.se``
  to IPv4 addresses, and bring the interface down, repeated five times with a
  three-second delay between iterations.
- ``test_iconfig``: connect to the access point, fetch device configuration over
  HTTPS using client credentials, and bring the interface down, repeated three
  times. The endpoint and device identity are configured in
  ``config/src/utils_iconfig.c``.

The Wi-Fi helper enables power save before connecting, with a listen interval
of 10 and a timeout of 4000 ms. These values are defined in
``config/src/utils_iface_wifi.c``. Test execution order should not be assumed
to match source-file order.

 
Configuration
*************

Wi-Fi Credentials
=================

Create or update ``config/src/env_config.h`` locally with the access point's
credentials:

.. code-block:: c

   #ifndef ENV_CONFIG_H
   #define ENV_CONFIG_H

   #define ENV_SSID "YOUR_WIFI_SSID"
   #define ENV_PSK "YOUR_WIFI_PASSWORD"

   #endif

This file is Git-ignored. Do not commit real network credentials.

HTTPS Credentials
=================

The HTTPS helper includes these resource headers:

- ``config/resources/ca_iconfig.der.h``
- ``config/resources/J3APC0006A_cert.h``
- ``config/resources/J3APC0006A_key.h``

Provide credentials appropriate for your test device and endpoint. When
replacing them, update the header references, array names, and device identity
in ``config/src/utils_iconfig.c`` as necessary. The private-key header is
Git-ignored and must be supplied locally; never commit production private keys.
Firmware containing credentials must also be handled as sensitive material.

Application and Board Settings
==============================

``prj.conf`` enables ztest, networking, Wi-Fi, DNS, HTTP, TLS, and the required
stack and heap sizes. ``config/Kconfig`` includes the Zephyr and USB sample
Kconfig definitions; it does not replace ``prj.conf``.

With the standard build commands below, Zephyr automatically loads the
matching ``boards/<board>.conf`` and ``boards/<board>.overlay``. Board
configuration overrides duplicate application settings. Do not specify a
custom ``CONF_FILE`` unless you also account for board configuration selection.

Requirements
************

#. nrf5340dk + EK-RA6W1 (SPI)

To connect the nrf5340dk to the EK-RA6W1 using the SPI bus use jumper wires to
connect the following pins:

+---------------+-------------------+
| NRF           | EK-RA6W1          |
+---------------+-------------------+
| P1_15 (SCK)   | P0_08 (SCK)       |
+---------------+-------------------+
| P1_12 (CS)    | P0_09 (CS)        |
+---------------+-------------------+
| P1_13 (MOSI)  | P0_11 (MOSI)      |
+---------------+-------------------+
| P1_14 (MISO)  | P0_10 (MISO)      |
+---------------+-------------------+
| P0_24 (INT)   | P0_12 (INT)       |
+---------------+-------------------+
| P1_11 (RST)   | RST_N (RST)       |
+---------------+-------------------+
| P0_10         | P0_13 (GPIO)      |
+---------------+-------------------+

#. nrf54lm20dk + EK-RA6W1 (SPI)
 
To connect the nrf54lm20dk to the EK-RA6W1 using the SPI bus use jumper wires to
connect the following pins:
 
+---------------+-------------------+
| NRF           | EK-RA6W1          |
+---------------+-------------------+
| P1_15 (SCK)   | P0_08 (SCK)       |
+---------------+-------------------+
| P1_12 (CS)    | P0_09 (CS)        |
+---------------+-------------------+
| P1_13 (MOSI)  | P0_11 (MOSI)      |
+---------------+-------------------+
| P1_14 (MISO)  | P0_10 (MISO)      |
+---------------+-------------------+
| P1_10 (INT)   | P0_12 (INT)       |
+---------------+-------------------+
| P1_11 (RST)   | RST_N (RST)       |
+---------------+-------------------+
| P0_03         | P0_13 (GPIO)      |
+---------------+-------------------+

Building and Running
********************

Build and flash for the nrf5340dk connected to the RRQ61051EVZ using the MikroBUS SPI interface:

.. code-block:: none

   west build pnet_shell -b nrf5340dk/nrf5340/cpuapp -p always 
   west flash


Build and flash for the nrf54lm20dk connected to the RRQ61051EVZ using the MikroBUS SPI interface:

.. code-block:: none

   west build pnet_shell -b nrf54lm20dk/nrf54lm20a/cpuapp -p always   west flash
   west flash

After flashing, you can observe the state of the application via the console.

