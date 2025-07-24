Overview
********

Example implementation of a Zephyr based TCP server using a Wi-Fi interface.
The Wi-Fi interface operates in station mode. The SSID and password of the 
Wi-Fi Access Point to which it will connect are configured via the following
macros:

.. code-block:: AP

   #define WIFI_SSID            "TP-Link_1218" 
   #define WIFI_PSK             "74512829"

The application acts as a TCP echo server, transmitting any data received
back to the client. The port number of the server is configured via the
following macro:

.. code-block:: SERVER

   #define SERVER_PORT          53704

Received data is printed to the console.

Requirements
************

The following board configurations are currently supported:

#. EK-RA8M1 + QCIOT-RRQ61051EVZ (PMOD UART)

Connect the QCIOT-RRQ61051EVZ to the PMOD1 interface on the EK-RA8M1 and the
following pins will be used:

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

Building and Running
********************

Build and flash for the EK-RA8M1 connected to the RRQ61051EVZ using the PMOD UART interface:

.. code-block:: none

   west build wifi_sta_tcp_server -b ek_ra8m1 -p always -DSHIELD=renesas_qciot_rrq61051evz_pmod
   west flash

After flashing, you can observe the state of the application via the console.
