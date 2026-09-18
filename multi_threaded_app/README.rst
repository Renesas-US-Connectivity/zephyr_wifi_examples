Overview
********

**multi_threaded_app** is an autonomous Zephyr networking application that
boots directly into a multi-threaded Wi-Fi, HTTPS, MQTT, and UDP customer flow.
Unlike ``pnet_shell``, this application does not expose an interactive shell
workflow. It starts its worker threads automatically at boot and manages
connection, provisioning, telemetry, and recovery without recompilation-time
operator input.

Key Features
============

- **Autonomous startup flow**: Starts four dedicated threads for Wi-Fi/MQTT
   control, MQTT polling, periodic publish, and UDP traffic.
- **Wi-Fi bring-up with DHCP**: Connects to the configured SSID and waits for
   IPv4 address assignment before continuing.
- **HTTPS provisioning step**: Performs an HTTPS GET to retrieve MQTT endpoint
   information and optional PEM credentials.
- **MQTT over TLS**: Connects to the broker with TLS, subscribes once, and
   keeps the session alive in a dedicated poll thread.
- **Periodic publish path**: Publishes MQTT data at a fixed interval in steady
   state.
- **Parallel UDP path**: Sends and receives UDP traffic independently from the
   MQTT path for concurrent socket validation.
- **Power-save validation**: Enables Wi-Fi power save after MQTT connection and
   disables it again during recovery.
- **Runtime diagnostics**: Logs Wi-Fi firmware version, RSSI, connection state,
   DNS resolution, and reconnect transitions.

Runtime Flow
============

At boot, the application starts the following threads:

- ``mt_flow``: Main Wi-Fi and MQTT connect/reconnect state machine
- ``mt_mqtt_poll``: MQTT keepalive, poll, and ping handling
- ``mt_publish``: Periodic MQTT publish and optional DNS diagnostics
- ``mt_udp``: Periodic UDP transmit and receive handling

The default flow is:

#. Connect to the configured Wi-Fi network
#. Wait for DHCP completion
#. Perform a one-time HTTPS GET for MQTT configuration and certificates
#. Resolve the MQTT host if needed
#. Connect to the MQTT broker over TLS
#. Enable Wi-Fi power save
#. Subscribe to the configured MQTT topic
#. Enter steady state with periodic MQTT publish and UDP traffic

Stage Details and APIs
======================

The implementation is split mainly between ``src/pnet_multi_threaded.c`` and
``src/https_get.c``. The sections below describe what each stage does and the
main Zephyr APIs involved.

Stage 0: Application startup
----------------------------

At boot, ``mt_app_init()`` registers the network event callbacks and starts the
four worker threads.

- ``net_mgmt_init_event_callback()`` and ``net_mgmt_add_event_callback()`` are
   used to subscribe to Wi-Fi and DHCP events.
- ``k_thread_create()`` starts ``mt_flow``, ``mt_mqtt_poll``, ``mt_publish``,
   and ``mt_udp``.
- ``SYS_INIT()`` registers the application init function so the flow starts
   automatically during system startup.

Stage 1: Wi-Fi connect
----------------------

The ``mt_flow`` thread handles initial Wi-Fi bring-up and recovery after link
loss.

- ``net_if_get_default()`` selects the default network interface.
- ``net_if_is_up()`` and ``net_if_up()`` make sure the interface is enabled
   before connect.
- ``net_mgmt(NET_REQUEST_WIFI_VERSION, ...)`` queries driver and firmware
   version information.
- ``net_mgmt(NET_REQUEST_WIFI_CONNECT, ...)`` submits a
   ``wifi_connect_req_params`` request using the configured SSID and PSK.
- The Wi-Fi result is observed through the ``NET_EVENT_WIFI_CONNECT_RESULT``
   callback, which updates the shared connection state.

Stage 2: DHCP completion
------------------------

After Wi-Fi association, the flow waits until the interface receives an IPv4
address.

- ``NET_EVENT_IPV4_DHCP_BOUND`` is handled by the IPv4 callback.
- ``k_event_post()``, ``k_event_clear()``, and ``k_event_wait()`` synchronize
   the connect flow with DHCP completion.
- ``net_addr_ntop()`` formats the assigned IP address for logging.

Stage 3: HTTPS provisioning
---------------------------

The one-time HTTPS stage is implemented by ``https_phase1_get()`` in
``src/https_get.c``. It retrieves MQTT endpoint information and optional PEM
credentials from a JSON response.

- ``zsock_socket(..., SOCK_STREAM, IPPROTO_TLS_1_2)`` creates the TLS socket.
- ``zsock_setsockopt()`` configures TLS options such as ciphers, hostname, peer
   verification, and security tags.
- ``zsock_connect()`` opens the TCP/TLS connection to the provisioning server.
- ``http_client_req()`` sends the HTTP GET request and receives the response.
- ``tls_credential_add()`` and ``tls_credential_delete()`` manage temporary TLS
   credentials when that path is enabled.
- The JSON payload is parsed into ``struct https_mqtt_cfg`` so the MQTT stage
   can use provisioned host, port, client ID, and certificates.

Stage 4: MQTT host resolution
-----------------------------

Before connecting to the broker, the flow validates whether the configured MQTT
host is already a literal IPv4 address or must be resolved through DNS.

- ``zsock_inet_pton()`` checks whether the MQTT host is a numeric IP string.
- ``zsock_getaddrinfo()`` resolves host names when DNS is required.
- ``zsock_freeaddrinfo()`` releases the DNS result after use.

Stage 5: MQTT/TLS connect
-------------------------

The MQTT session is established by ``mt_mqtt_do_connect()``.

- ``mqtt_client_init()`` initializes the Zephyr MQTT client structure.
- ``mqtt_connect()`` starts the broker connection.
- ``mqtt_input()`` processes incoming MQTT packets.
- ``mqtt_live()`` drives the keepalive logic while the connection is active.
- ``tls_credential_add()`` loads the CA certificate, client certificate, and
   private key for the MQTT security tag when TLS is used.
- ``mt_mqtt_evt_handler()`` processes ``MQTT_EVT_CONNACK``,
   ``MQTT_EVT_DISCONNECT``, ``MQTT_EVT_SUBACK``, ``MQTT_EVT_PUBACK``, and
   ``MQTT_EVT_PUBLISH`` events.

Stage 6: Power-save enable
--------------------------

Once MQTT is up, the flow enables Wi-Fi power save.

- ``net_mgmt(NET_REQUEST_WIFI_PS, ...)`` sends a ``wifi_ps_params`` request to
   enable or disable power-save mode.
- The current state is tracked in shared variables and included in telemetry
   logs and MQTT payloads.

Stage 7: MQTT subscribe
-----------------------

The application subscribes once to the configured topic after the broker
session is stable.

- ``mqtt_subscribe()`` sends the subscription request.
- The code waits for ``MQTT_EVT_SUBACK`` before marking the subscription as
   complete.
- For incoming QoS 1 publishes, ``mqtt_publish_qos1_ack()`` acknowledges the
   message after the payload is read.

Stage 8: Periodic MQTT publish
------------------------------

The ``mt_publish`` thread runs independently from the connection state machine
and publishes telemetry at a fixed interval.

- ``snprintk()`` builds a JSON payload with uptime, RSSI, and power-save state.
- ``mqtt_publish()`` sends the message using QoS 1.
- The publish path waits for ``MQTT_EVT_PUBACK`` before treating the send as
   successful.
- When periodic DNS diagnostics are enabled, ``zsock_getaddrinfo()`` is also
   used here to resolve public hosts during steady state.

Stage 9: Parallel UDP traffic
-----------------------------

The ``mt_udp`` thread validates concurrent socket use while MQTT and DNS are
also active.

- ``zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)`` creates the UDP socket.
- ``zsock_bind()`` binds the local UDP port.
- ``zsock_setsockopt(..., SO_RCVTIMEO, ...)`` sets a receive timeout.
- ``zsock_sendto()`` transmits the probe datagram.
- ``zsock_recvfrom()`` waits for the response and measures round-trip time.
- ``net_addr_ntop()`` formats the peer address for logging.

Stage 10: Polling, keepalive, and recovery
------------------------------------------

The application keeps MQTT responsive in a dedicated poll thread and recovers
when Wi-Fi or MQTT drops.

- ``zsock_poll()`` waits for MQTT socket readability.
- ``mqtt_input()`` consumes inbound broker traffic when data is available.
- ``mqtt_live()`` services protocol keepalive.
- ``mqtt_ping()`` is scheduled through ``k_work_delayable`` for periodic ping
   transmission.
- ``mqtt_disconnect()`` and ``zsock_close()`` are used during teardown.
- When a failure is detected, the flow thread clears state, disables power save,
   and restarts from Wi-Fi connect or MQTT reconnect as needed.

Configuration
=============

The application uses compile-time configuration values in
``src/pnet_multi_threaded.c`` for the default runtime setup, including:

- Wi-Fi SSID and PSK
- Default MQTT host, port, client ID, and topics
- Publish and UDP intervals
- UDP peer address and port

HTTPS provisioning support is implemented in ``src/https_get.c`` and can
override the default MQTT endpoint and TLS credential material at runtime.

Typical Use Cases
=================

- End-to-end Wi-Fi to cloud connectivity validation
- MQTT/TLS session bring-up and reconnect testing
- HTTPS-based device provisioning experiments
- Concurrent MQTT and UDP socket stress checks
- Power-save transition and recovery verification
- RSSI and connectivity diagnostics during long-running tests

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

Run the following commands from the ``multi_threaded_app`` directory.

Build and flash for the EK-RA8M1 connected to the RRQ61051EVZ using the PMOD UART interface:

.. code-block:: none

   west build -b ek_ra8m1 -p always . -DSHIELD=renesas_qciot_rrq61051evz_pmod
   west flash

Build and flash for the EK-RA8M1 connected to the RRQ61051EVZ using the MikroBUS UART interface:

.. code-block:: none

   west build -b ek_ra8m1 -p always . -DSHIELD=renesas_qciot_rrq61051evz_mikrobus_uart
   west flash

Build and flash for the nrf5340dk connected to the RRQ61051EVZ using the MikroBUS SPI interface:

.. code-block:: none

   west build -b nrf5340dk/nrf5340/cpuapp -p always .
   west flash

Build and flash for the EK-RA6M4 connected to the RRQ61051EVZ using the MikroBUS SPI interface:

.. code-block:: none

   west build -b ek_ra6m4 -p always . -DSHIELD=renesas_qciot_rrq61051evz_mikrobus_spi
   west flash

Build and flash for the nrf52840dk connected to the RRQ61051EVZ using the MikroBUS SPI interface:

.. code-block:: none

   west build -b nrf52840dk/nrf52840 -p always .
   west flash

Build and flash for the nrf54lm20dk connected to the RRQ61051EVZ using the MikroBUS SPI interface:

.. code-block:: none

   west build -b nrf54lm20dk/nrf54lm20a/cpuapp -p always .
   west flash

Additional board-specific configuration files are also present for
``nrf7002dk/nrf5340/cpuapp``, ``nrf9160dk/nrf9160``, and
``nrf9160dk/nrf9160/ns``.

After flashing, observe the console output for the autonomous startup phases,
including Wi-Fi connection, DHCP, HTTPS provisioning, MQTT/TLS connection,
subscription, and steady-state publish and UDP activity.

