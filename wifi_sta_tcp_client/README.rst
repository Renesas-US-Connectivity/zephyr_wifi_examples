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

#. EK-RA6M4 + EK-RA6W1 connected using a 4-wire UART as follows:

+------------+-------------+
| EK-RA6M4   | EK-RA6W1    |
+------------+-------------+
| P610 (CTS) | P0_08 (RTS) |
+------------+-------------+
| P611 (RTS) | P0_07 (CTS) |
+------------+-------------+
| P613 (TXD) | P0_04 (RXD) |
+------------+-------------+
| P614 (RXD) | P0_05 (TXD) |
+------------+-------------+

Building and Running
********************

Build and flash for the EK-RA6M4 and the RA6W1 WIFI board:

.. code-block:: none

   west build -b ek_ra6m4 wifi_sta_tcp_client -p always
   west flash

After flashing, you can observe the state of the application via the console.
