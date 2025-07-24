Overview
********

Example implementation of a Zephyr based TCP client using a Wi-Fi interface.
The Wi-Fi interface operates in station mode. The SSID and password of the 
Wi-Fi Access Point to which it will connect are configured via the following
macros:

.. code-block:: AP

   #define WIFI_SSID            "TP-Link_1218" 
   #define WIFI_PSK             "74512829"

The application transmits data to a TCP server and then waits for a response.
The address and port number of the server are configured via the following
macros:

.. code-block:: SERVER

   #define SERVER_IP            "192.168.0.101"
   #define SERVER_PORT          53703

Once a response has been received it is printed to the console.

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

   west build wifi_sta_tcp_client -b ek_ra8m1 -p always -DSHIELD=renesas_qciot_rrq61051evz_pmod
   west flash

After flashing, you can observe the state of the application via the console.
