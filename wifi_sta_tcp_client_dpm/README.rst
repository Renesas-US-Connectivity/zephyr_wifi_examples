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
| P409 (INT)  | P0_07 (INT)       |
+-------------+-------------------+
| P115 (RST)  | RST_N (RST)       |
+-------------+-------------------+

Building and Running
********************

Build and flash for the EK-RA8M1 connected to the RRQ61051EVZ using the PMOD UART interface:

.. code-block:: none

   west build wifi_sta_tcp_client -b ek_ra8m1 -p always -DSHIELD=renesas_qciot_rrq61051evz_pmod
   west flash

Build and flash for the EK-RA8M1 connected to the RRQ61051EVZ using the MikroBUS UART interface:

.. code-block:: none

   west build wifi_sta_tcp_client -b ek_ra8m1 -p always -DSHIELD=renesas_qciot_rrq61051evz_mikrobus_uart
   west flash

Build and flash for the EK-RA6M4 connected to the RRQ61051EVZ using the MikroBUS SPI interface:

.. code-block:: none

   west build wifi_sta_tcp_client -b ek_ra6m4 -p always -DSHIELD=renesas_qciot_rrq61051evz_mikrobus_spi
   west flash

After flashing, you can observe the state of the application via the console.
