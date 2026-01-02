.. zephyr:code-sample:: tls-https-client
   :name: TLS HTTPS Client
   :relevant-api: bsd_sockets dns_resolve tls_credentials net_if wifi_mgmt

   Secure HTTPS client using TLS 1.2 encryption with certificate validation.

Overview
********

This sample application demonstrates a standalone HTTPS client that establishes
secure connections to public HTTPS servers using TLS 1.2 encryption. Key features include:

- WiFi connectivity with SSID and BSSID matching
- Acquiring a DHCPv4 lease from WiFi network
- DNS resolution for domain names
- Establishing a secure TLS 1.2 connection to HTTPS servers
- X.509 certificate validation using Amazon Root CA 1
- HTTP/1.1 GET request transmission
- Encrypted payload transmission and reception
- Proper TLS session closure with close_notify alert
- Comprehensive error handling and logging

Requirements
************

- WiFi-capable Zephyr-supported microcontroller
- Network connectivity to WiFi access point
- Access to public HTTPS endpoint (e.g., httpbin.org)
- An entropy source for TLS random number generation

Supported Boards
================

- Renesas EK-RA6M4 with RRQ61051EVZ WiFi Shield (tested)
- ST NUCLEO-F429ZI
- Pinnacle 100 DVK
- MG100
- QEMU x86

Building and Running
********************

Build the application for Renesas EK-RA6M4 board:

.. code-block:: console

   west build zephyr_wifi_examples_tls/tls_https_client -b ek_ra6m4 \
       -DSHIELD=renesas_qciot_rrq61051evz_mikrobus_spi

Flash to device:

.. code-block:: console

   west flash

Monitor device output:

.. code-block:: console

   screen /dev/ttyACM0 115200
   # or
   minicom -D /dev/ttyACM0 -b 115200

Configuration
*************

WiFi Settings
=============

Configure WiFi credentials in :zephyr_file:`tls_https_client/src/main.c`:

- :c:macro:`WIFI_SSID`: Your WiFi network name (default: "ITP-FF")
- :c:macro:`WIFI_PSK`: Your WiFi password (default: "WiFiNetge@r@1")
- :c:macro:`WIFI_BSSID`: Target AP MAC address (optional, for specific AP selection)

HTTPS Server Configuration
===========================

Customize target HTTPS server in :zephyr_file:`tls_https_client/src/main.c`:

- :c:macro:`HTTPS_SERVER`: Target server hostname (default: "httpbin.org")
- :c:macro:`HTTPS_PORT`: HTTPS port number (default: 443)
- :c:macro:`HTTPS_PATH`: HTTP request path (default: "/get")

Certificate Management
======================

The application includes Amazon Root CA 1 certificate for validating HTTPS servers.
To use a different CA certificate:

1. Replace :zephyr_file:`src/creds/AmazonRootCA1.pem` with your CA certificate
2. Run the conversion script: ``python3 src/creds/convert_key.py``
3. Rebuild the application

Sample Output
=============

Typical device console output during successful HTTPS connection:

.. code-block:: console

   [00:00:00.000,000] <inf> https: Starting HTTPS client application...
   [00:00:03.000,000] <inf> https: iface found
   [00:00:03.100,000] <inf> https: callback registered
   [00:00:05.000,000] <inf> https: BSSID found during scan
   [00:00:08.000,000] <inf> https: Connected to AP!
   [00:00:15.000,000] <inf> https: DHCP bound - we have an IP address!
   [00:00:18.000,000] <inf> https: Credentials setup completed
   [00:00:18.100,000] <inf> https: Starting HTTPS client connection to httpbin.org:443
   [00:00:18.200,000] <inf> https: TLS socket created successfully
   [00:00:18.300,000] <inf> https: Connecting to HTTPS server at port 443...
   [00:00:19.000,000] <inf> https: HTTPS connection established
   [00:00:19.100,000] <inf> https: HTTP request sent (96 bytes)
   [00:00:20.000,000] <inf> https: Response received (467 bytes)
   [00:00:20.100,000] <inf> https: Response:
   HTTP/1.1 200 OK
   Date: Fri, 02 Jan 2026 08:26:10 GMT
   Content-Type: application/json
   {
      "args": {},
      "headers": {
         "Host": "httpbin.org",
         "User-Agent": "Zephyr-HTTPS-Client/1.0"
      }
   }
   [00:00:20.200,000] <inf> https: HTTPS client completed successfully
   [00:00:20.300,000] <inf> https: Application finished, entering idle loop

Performance Characteristics
===========================

Typical timing breakdown on Renesas EK-RA6M4:

- WiFi Scan & Connect: 8-15 seconds
- DHCP IP Acquisition: 5-10 seconds
- DNS Resolution: 1-2 seconds
- TLS Handshake: 2-3 seconds
- HTTP Request/Response: 500ms - 1 second
- Total Startup to Response: 30-40 seconds

Memory Usage
============

- FLASH: ~293 KB (27.96% of 1 MB)
- RAM: ~205 KB (78.38% of 256 KB)

Security Features
=================

- TLS 1.2 Protocol (RFC 5246)
- X.509 Certificate Validation
- Certificate Chain Validation
- Server Name Indication (SNI)
- Encrypted Payload Transmission
- HMAC-SHA256 Message Authentication
- Perfect Forward Secrecy (when supported)

Troubleshooting
===============

WiFi Connection Issues
""""""""""""""""""""""

If WiFi connection fails, verify:

- SSID and password are correct
- WiFi AP is in range and broadcasting
- BSSID (MAC address) is correct if using BSSID matching
- WiFi driver firmware is up to date

TLS Handshake Failures
""""""""""""""""""""""

If TLS handshake fails:

- Verify CA certificate is correct and embedded
- Check device system time is correct
- Ensure target server certificate is valid
- Verify firewall allows port 443

DNS Resolution Failures
""""""""""""""""""""""

If DNS fails:

- Verify DNS server is reachable
- Check internet connectivity
- Try using IP address directly instead of hostname
- Verify firewall allows DNS (port 53)

References
==========

- `Zephyr RTOS Documentation <https://docs.zephyrproject.org/>`_
- `RFC 5246 - TLS 1.2 <https://tools.ietf.org/html/rfc5246>`_
- `X.509 Certificates <https://tools.ietf.org/html/rfc5280>`_
- `HTTPS Protocol <https://tools.ietf.org/html/rfc2818>`_
- `Amazon Root CA 1 <https://www.amazontrust.com/repository/>`_
