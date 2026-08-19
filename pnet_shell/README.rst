Overview
********

**pnet_shell** is an interactive Zephyr-based network testing and debugging application for Wi-Fi and TCP connectivity. It provides a command-line shell interface to dynamically control Wi-Fi connections, manage network interfaces, and perform TCP operations without requiring firmware recompilation.

Key Features
============

- **Dynamic Wi-Fi Connections**: Connect to Wi-Fi networks with or without passwords (open network support)
- **BSSID-Specific Connections**: Connect to specific access points by BSSID when multiple networks with the same SSID are present
- **Flexible Security Modes**: Automatically selects appropriate security type (NONE for open networks, WPA_AUTO_PERSONAL for secured networks)
- **TCP Operations**: Establish TCP connections and transmit/receive data for network testing
- **Power Management Testing**: Configure and test Wi-Fi power-save modes and listen intervals
- **DNS Resolution**: Test DNS resolution with caching and resolver diagnostics
- **Network Diagnostics**: Monitor network state, interface status, and socket offload capabilities
- **Shell Interface**: Interactive command prompt for testing multiple scenarios without recompilation

Typical Use Cases
=================

- Debugging Wi-Fi connectivity issues with different access points
- Testing open network connections (no password required)
- Testing secured network connections with WPA/WPA2/WPA3
- Verifying power-save and low-power mode behavior
- Testing TCP client communication with remote servers
- Validating DNS resolution in various network configurations
- Troubleshooting BSSID-specific roaming scenarios

Commands Overview
==================

**Wi-Fi Commands**:

- ``pnet connect <ssid> [psk]`` — Connect to SSID; password optional for open networks
- ``pnet connect_bssid <ssid> [psk] <bssid>`` — Connect to specific BSSID; password optional

**TCP Commands**:

- ``pnet tcp_connect <ip> <port>`` — Establish TCP connection to server
- ``pnet tcp_send <data>`` — Send data over active TCP connection

**Power Management Commands**:

- ``pnet ps <0|1>`` — Enable (1) or disable (0) Wi-Fi power-save mode

**Diagnostic Commands**:

- ``pnet init`` — Initialize Wi-Fi interface

Requirements
************

The following board configurations are currently supported:

#. EK-RA8M1 + QCIOT-RRQ61051EVZ (PMOD UART)

Connect the QCIOT-RRQ61051EVZ to the PMOD1 interface on the EK-RA8M1 (the
following pins will be used):

+------------+-------------------+
| EK-RA8M1   | QCIOT-RRQ61051EVZ |
+------------+-------------------+
| P613 (CTS) | P0_08 (RTS)       |
+------------+-------------------+
| P612 (RTS) | P0_09 (CTS)       |
+------------+-------------------+
| P609 (TXD) | P0_05 (RXD)       |
+------------+-------------------+
| P610 (RXD) | P0_12 (TXD)       |
+------------+-------------------+
| PA08 (RST) | RST_N (RST)       |
+------------+-------------------+

#. EK-RA8M1 + QCIOT-RRQ61051EVZ (MikroBUS UART)

Connect the QCIOT-RRQ61051EVZ to the MikroBUS interface on the EK-RA8M1 (the
following pins will be used):

+------------+-------------------+
| EK-RA8M1   | QCIOT-RRQ61051EVZ |
+------------+-------------------+
| P310 (TXD) | P0_05 (RXD)       |
+------------+-------------------+
| P309 (RXD) | P0_12 (TXD)       |
+------------+-------------------+
| P502 (RST) | RST_N (RST)       |
+------------+-------------------+

#. EK-RA6M4 + EK-RA6W1 (SPI)

To connect the EK-RA6M4 to the EK-RA6W1 using the SPI bus use jumper wires to
connect the following pins:

+-------------+-------------------+
| EK-RA6M4    | EK-RA6W1          |
+-------------+-------------------+
| P204 (SCK)  | P0_08 (SCK)       |
+-------------+-------------------+
| P205 (CS)   | P0_09 (CS)        |
+-------------+-------------------+
| P203 (MOSI) | P0_11 (MOSI)      |
+-------------+-------------------+
| P202 (MISO) | P0_10 (MISO)      |
+-------------+-------------------+
| P409 (INT)  | P0_12 (INT)       |
+-------------+-------------------+
| P115 (RST)  | RST_N (RST)       |
+-------------+-------------------+
| P206        | P0_13 (GPIO)      |
+-------------+-------------------+

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

Build and flash for the EK-RA8M1 connected to the RRQ61051EVZ using the PMOD UART interface:

.. code-block:: none

   west build pnet_shell -b ek_ra8m1 -p always -DSHIELD=renesas_qciot_rrq61051evz_pmod
   west flash

Build and flash for the EK-RA8M1 connected to the RRQ61051EVZ using the MikroBUS UART interface:

.. code-block:: none

   west build pnet_shell -b ek_ra8m1 -p always -DSHIELD=renesas_qciot_rrq61051evz_mikrobus_uart
   west flash

Build and flash for the nrf5340dk connected to the RRQ61051EVZ using the MikroBUS SPI interface:

.. code-block:: none

   west build pnet_shell -b nrf5340dk/nrf5340/cpuapp -p always 
   west flash

Build and flash for the EK-RA6M4 connected to the RRQ61051EVZ using the MikroBUS SPI interface:

.. code-block:: none

   west build pnet_shell -b ek_ra6m4 -p always -DSHIELD=renesas_qciot_rrq61051evz_mikrobus_spi
   west flash

Build and flash for the nrf52840dk connected to the RRQ61051EVZ using the MikroBUS SPI interface:

.. code-block:: none

   west build pnet_shell -b nrf52840dk/nrf52840 -p always 
   west flash

Build and flash for the nrf54lm20dk connected to the RRQ61051EVZ using the MikroBUS SPI interface:

.. code-block:: none

   west build pnet_shell -b nrf54lm20dk/nrf54lm20a/cpuapp -p always   west flash
   west flash

After flashing, you can observe the state of the application via the console.

