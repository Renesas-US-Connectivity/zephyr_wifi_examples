Overview
********

**pnet_multi_thread_https** is an autonomous Zephyr network application that runs a customer flow continuously at boot, without shell commands.

The app brings up Wi-Fi, performs an HTTPS bootstrap to fetch MQTT endpoint data and optional client credentials, connects to MQTT over TLS, enables power-save, subscribes to a topic, publishes telemetry periodically, runs DNS diagnostics, and executes a parallel UDP probe thread for runtime validation.

Configuration Note
==================

The current sample is configured with hardcoded environment values in the application source. Before using it in a different lab or customer setup, update the following items to match your environment:

- Wi-Fi SSID and PSK
- HTTPS provisioning server IP, port, and path
- MQTT broker host, port, and client ID fallback values
- Publish and subscribe topic names
- UDP diagnostic target IP and ports
- Any certificate or provisioning infrastructure assumptions

At present these values are not read from Kconfig, shell input, or runtime storage. They must be edited in the source to match the target setup.

Key Features
============

- Autonomous startup (no interactive command dependency)
- Multi-threaded architecture with dedicated flow, MQTT poll, publish, and UDP workers
- HTTPS bootstrap for MQTT endpoint and optional PEM credential delivery
- MQTT over TLS with periodic keepalive ping handling
- QoS1 telemetry publish with PUBACK verification
- One-time topic subscribe plus inbound message logging
- Periodic DNS resolution to validate resolver/socket behavior during steady state
- Parallel UDP probe/echo validation while MQTT and DNS are active
- Wi-Fi and MQTT loss detection with automatic recovery loop

Thread Model
============

The application starts four threads:

- ``mt_flow`` (priority 6): Wi-Fi, HTTPS bootstrap, MQTT state machine, power-save control, subscribe, and recovery
- ``mt_mqtt_poll`` (priority 7): MQTT input polling, keepalive, and periodic ping sending
- ``mt_publish`` (priority 8): periodic telemetry publish every 60 seconds and DNS validation
- ``mt_udp`` (priority 9): UDP probe send/receive every 30 seconds with RTT logging after HTTPS phase completes

Application Flow
================

At boot, event handlers are registered and all four threads are created. The runtime flow is:

1. **Phase 1 - Wi-Fi + DHCP**

   - Bring up the default interface if needed.
   - Connect to configured SSID/PSK.
   - Wait for DHCP bound event.

2. **Phase 2 - HTTPS bootstrap**

   - Start an HTTPS GET to the configured provisioning server.
   - Retrieve MQTT endpoint information from JSON returned by the server.
   - If the JSON includes ``mqtt_ca_pem``, ``mqtt_client_cert_pem``, and ``mqtt_private_key_pem``, store them in RAM for the upcoming MQTT TLS session.
   - If PEM fields are missing or invalid, continue with the compiled fallback MQTT endpoint and flash-stored certificate material.
   - Mark the HTTPS bootstrap phase complete so the UDP worker can start normal operation.

3. **Phase 3 - Broker address check**

   - If broker host is a literal IPv4 address, skip DNS.
   - Otherwise resolve via ``getaddrinfo`` and continue only on success.

4. **Phase 4 - MQTT connect (TLS)**

   - Initialize MQTT client and broker socket settings.
   - Select MQTT credentials from the HTTPS bootstrap result when valid; otherwise use built-in fallback credentials.
   - Connect and wait for CONNACK.
   - Start MQTT poll/keepalive operation.

5. **Phase 5 - Enable Power Save**

   - Enable Wi-Fi power-save using Wi-Fi management API.

6. **Phase 6 - Subscribe**

   - Subscribe once to the configured downstream topic.
   - Enter steady state.

7. **Steady state operation**

   - MQTT input processing runs continuously in the poll thread.
   - MQTT keepalive ping is transmitted periodically to keep the broker session active.
   - Telemetry is published every 60 seconds using QoS1, and PUBACK is expected for each message.
   - The publish payload includes runtime state such as uptime, latest RSSI, and power-save status.
   - After each publish cycle, a DNS lookup is performed against rotating public hosts to validate resolver behavior while MQTT and UDP traffic are active.
   - The UDP diagnostic worker sends a probe every 30 seconds and measures response RTT from the configured echo target.
   - Host diagnostics periodically log RSSI, Wi-Fi state, MQTT state, and power-save state.

8. **Recovery behavior**

   - On Wi-Fi loss: stop MQTT loop, cancel ping work, disable power-save, return to Phase 1.
   - On MQTT loss: stop MQTT loop, cancel ping work, disable power-save, reconnect from Phase 3.

Sequence View
=============

The following timeline shows how the four threads cooperate during startup and steady state.

.. code-block:: none

   Boot
    |
    +--> mt_app_init: register Wi-Fi/DHCP callbacks
    +--> start threads: mt_flow | mt_mqtt_poll | mt_publish | mt_udp
      |
      +--> mt_flow
         1) Wi-Fi connect -> wait DHCP bound
         2) HTTPS GET -> parse MQTT host/port/client_id
            -> optionally parse MQTT CA/client cert/private key PEMs
         3) Broker host check (literal IP or DNS)
         4) MQTT connect -> wait CONNACK
         5) Enable PS
         6) Subscribe ra6w1_sub -> wait SUBACK
         7) Monitor Wi-Fi/MQTT link health
            |
            +--> if Wi-Fi lost: disable PS, stop ping work, restart at step 1
            +--> if MQTT lost: disable PS, stop ping work, restart at step 3

      +--> mt_mqtt_poll (every loop)
         - poll socket input
         - run mqtt_live keepalive
         - send MQTT ping every 30s

      +--> mt_publish (every 60s)
         - publish telemetry to ra6w1_pub (QoS1)
         - wait PUBACK
         - resolve rotating public hosts (DNS validation)
         - include RSSI / uptime / PS status in payload

      +--> mt_udp (every 30s)
         - wait until HTTPS bootstrap phase has completed
         - ensure Wi-Fi is up
         - create/bind UDP socket lazily if needed
         - send probe to target
         - wait for echo response and log RTT

Socket Activity During Steady State
===================================

- DNS resolver UDP socket (created by resolver)
- HTTPS TCP/TLS socket during bootstrap only
- MQTT TCP/TLS socket (broker session)
- UDP diagnostic socket (application probe thread)

This concurrent socket activity is intentional and is used to validate runtime behavior under power-save and mixed traffic. After bootstrap, the HTTPS socket is closed before long-running MQTT and UDP activity continues.

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

Building and Running
********************

Build and flash for the EK-RA8M1 connected to the RRQ61051EVZ using the PMOD UART interface:

.. code-block:: none

   west build pnet_multi_thread -b ek_ra8m1 -p always -DSHIELD=renesas_qciot_rrq61051evz_pmod
   west flash

Build and flash for the EK-RA8M1 connected to the RRQ61051EVZ using the MikroBUS UART interface:

.. code-block:: none

   west build pnet_multi_thread -b ek_ra8m1 -p always -DSHIELD=renesas_qciot_rrq61051evz_mikrobus_uart
   west flash

Build and flash for the nrf5340dk connected to the RRQ61051EVZ using the MikroBUS SPI interface:

.. code-block:: none

   west build pnet_multi_thread_https -b nrf5340dk/nrf5340/cpuapp -p always 
   west flash

Build and flash for the EK-RA6M4 connected to the RRQ61051EVZ using the MikroBUS SPI interface:

.. code-block:: none

   west build pnet_multi_thread -b ek_ra6m4 -p always -DSHIELD=renesas_qciot_rrq61051evz_mikrobus_spi
   west flash

Build and flash for the nrf52840dk connected to the RRQ61051EVZ using the MikroBUS SPI interface:

.. code-block:: none

   west build pnet_multi_thread -b nrf52840dk/nrf52840 -p always 
   west flash

Build and flash for the nrf54lm20dk connected to the RRQ61051EVZ using the MikroBUS SPI interface:

.. code-block:: none

   west build pnet_shell -b nrf54lm20dk/nrf54lm20a/cpuapp -p always   west flash
   west flash
   
After flashing, you can observe the state of the application via the console.

