Overview
********

**wifi_shell** is an interactive Zephyr shell application for the Renesas
eRPC Wi-Fi driver. It provides commands for Wi-Fi connection management,
power save, DNS resolution, HTTP, and authenticated HTTPS requests.
It does not run an automated ztest suite.


Shell Commands
==============

Application commands are registered under ``nt`` in ``src/shell.c``.
Enter ``nt --help`` at the serial console to list them.

- ``nt ver``: report the Wi-Fi driver and firmware versions.
- ``nt connect``: bring the interface up and connect using credentials from
  ``config/src/env_config.h``.
- ``nt connect "SSID" "PSK"``: connect using the supplied WPA-PSK credentials.
- ``nt disconnect``: disconnect from the access point.
- ``nt status``: report channel, RSSI, and BSSID.
- ``nt ps cfg``: apply the helper's power-save settings.
- ``nt ps on`` / ``nt ps off``: enable or disable power save.
- ``nt resolve <hostname>``: resolve a hostname to IPv4 addresses.
- ``nt http_get``: request ``http://www.google.com/``.
- ``nt https_get``: request ``https://www.google.com/`` without peer certificate
  verification. This is a connectivity check, not a secure HTTPS example.
- ``nt iconfig_fetch``: fetch device configuration over HTTPS using a CA
  certificate, client certificate, and private key. The endpoint and device
  identity are defined in ``config/src/utils_iconfig.c``.
- ``nt reset_float``: configure the Wi-Fi reset pin as an input.
- ``nt regulator on`` / ``nt regulator off``: control the Wi-Fi enable GPIO
  when the devicetree provides a ``wifi_enable`` node.

The connection helper enables power save before each connection, with a listen
interval of 10 and a timeout of 4000 ms. These values are defined in
``config/src/utils_iface_wifi.c``. Use ``nt ps off`` after connecting to disable
power save for subsequent requests. The connection helper waits up to 40000 ms
for a network event; check the console logs for the connection result.

The reset and regulator commands are hardware diagnostics and can interrupt
connectivity. Use them only with the corresponding board wiring in place.

 
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

This file is Git-ignored. Do not commit real network credentials. It must exist
at build time even when credentials will be supplied through ``nt connect``.
Credentials entered at the shell may be visible in terminal captures or history.

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

Run the following commands from the ``zephyr_wifi_examples`` directory in a
configured Zephyr workspace with the Renesas eRPC Wi-Fi module available.

Build and flash for the nrf5340dk connected to the EK-RA6W1 over SPI:

.. code-block:: none

  west build wifi_shell -b nrf5340dk/nrf5340/cpuapp -p always
  west flash


Build and flash for the nrf54lm20dk connected to the EK-RA6W1 over SPI:

.. code-block:: none

  west build wifi_shell -b nrf54lm20dk/nrf54lm20a/cpuapp -p always
  west flash

Open the board's serial console and wait for the ``uart:~$`` prompt. The
application does not connect automatically. A typical session is:

.. code-block:: none

  nt connect
  nt status
  nt ver
  nt resolve www.sunet.se
  nt iconfig_fetch
  nt disconnect

Wait for a successful connection and IPv4 address before running DNS or HTTP
commands. A successful iconfig request reports ``HTTP response complete,
status: OK, total body: ... bytes``. The response is device-specific and may
contain authentication tokens; do not publish sensitive response data.

