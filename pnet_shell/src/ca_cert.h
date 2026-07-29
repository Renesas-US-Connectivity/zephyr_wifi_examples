/*
 * ca_cert.h — CA certificate for MQTT TLS (port 8883)
 *
 * This is the CA certificate for test.mosquitto.org.
 * Source: https://test.mosquitto.org/ssl/mosquitto.org.crt
 *
 * To use a different broker, replace the PEM string below with your
 * broker's CA certificate in PEM format.
 */

#ifndef CA_CERT_H
#define CA_CERT_H

/* ================= Root CA ================= */
 
#define ROOT_CA \
"-----BEGIN CERTIFICATE-----\n" \
"MIICnDCCAkGgAwIBAgIJAM0wYdY5quqFMAoGCCqGSM49BAMCMGkxCzAJBgNVBAYT\n" \
"AktSMQ4wDAYDVQQIDAVTZW91bDEOMAwGA1UEBwwFU2VvdWwxEDAOBgNVBAoMB1Jl\n" \
"bmVzYXMxDTALBgNVBAsMBElJQlUxGTAXBgNVBAMMEFJvb3QgQ2VydGlmaWNhdGUw\n" \
"HhcNMjMwMzIzMDQwMTQwWhcNMzMwMzIwMDQwMTQwWjBpMQswCQYDVQQGEwJLUjEO\n" \
"MAwGA1UECAwFU2VvdWwxDjAMBgNVBAcMBVNlb3VsMRAwDgYDVQQKDAdSZW5lc2Fz\n" \
"MQ0wCwYDVQQLDARJSUJVMRkwFwYDVQQDDBBSb290IENlcnRpZmljYXRlMFkwEwYH\n" \
"KoZIzj0CAQYIKoZIzj0DAQcDQgAEqihf28i8BY434sE9V+fhS6S94hZpUKJAcuBr\n" \
"ZTZcKyE/PjvJmqSyWf5FvkeY49doR+9rCgaK5fDmn6aD+TgFu6OB0TCBzjAPBgNV\n" \
"HRMBAf8EBTADAQH/MB0GA1UdDgQWBBTuwab2GUr6mZBGAp41AqSZtp/hhjCBmwYD\n" \
"VR0jBIGTMIGQgBTuwab2GUr6mZBGAp41AqSZtp/hhqFtpGswaTELMAkGA1UEBhMC\n" \
"S1IxDjAMBgNVBAgMBVNlb3VsMQ4wDAYDVQQHDAVTZW91bDEQMA4GA1UECgwHUmVu\n" \
"ZXNhczENMAsGA1UECwwESUlCVTEZMBcGA1UEAwwQUm9vdCBDZXJ0aWZpY2F0ZYIJ\n" \
"AM0wYdY5quqFMAoGCCqGSM49BAMCA0kAMEYCIQDEgggVYtQtcM1RlHm2bvduDF+Y\n" \
"yAZAChjgyY3Ilm0OlwIhAPSJYYtLHyPeDMwenXMDk5dcll1ZLQZqfcubGHq2YA9n\n" \
"-----END CERTIFICATE-----\n"
 
 
/* ================= Client Certificate ================= */
 
#define CLIENT_CERT \
"-----BEGIN CERTIFICATE-----\n" \
"MIICoTCCAkigAwIBAgIJALrAHEerhG8bMAoGCCqGSM49BAMCMGkxCzAJBgNVBAYT\n" \
"AktSMQ4wDAYDVQQIDAVTZW91bDEOMAwGA1UEBwwFU2VvdWwxEDAOBgNVBAoMB1Jl\n" \
"bmVzYXMxDTALBgNVBAsMBElJQlUxGTAXBgNVBAMMEFJvb3QgQ2VydGlmaWNhdGUw\n" \
"HhcNMjMwMzIzMDQwMTQ5WhcNMzMwMzIwMDQwMTQ5WjBzMQswCQYDVQQGEwJLUjES\n" \
"MBAGA1UECAwJU29tZXdoZXJlMRIwEAYDVQQHDAlTb21ld2hlcmUxEDAOBgNVBAoM\n" \
"B1JlbmVzYXMxDTALBgNVBAsMBElJQlUxGzAZBgNVBAMMEkNsaWVudCBDZXJ0aWZp\n" \
"Y2F0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABElgzxeL2s4JemIC0n32Yrng\n" \
"cmCq/XwRCMGri1ZNDbnhRyNaHfclRwhEGWKiP64bTuq3HXb5yB0dQ5mp+5vHbh2j\n" \
"gc4wgcswDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUHrDENetRTmSpJKQ3T9mHew4f\n" \
"geUwgZsGA1UdIwSBkzCBkIAU7sGm9hlK+pmQRgKeNQKkmbaf4YahbaRrMGkxCzAJ\n" \
"BgNVBAYTAktSMQ4wDAYDVQQIDAVTZW91bDEOMAwGA1UEBwwFU2VvdWwxEDAOBgNV\n" \
"BAoMB1JlbmVzYXMxDTALBgNVBAsMBElJQlUxGTAXBgNVBAMMEFJvb3QgQ2VydGlm\n" \
"aWNhdGWCCQDNMGHWOarqhTAKBggqhkjOPQQDAgNHADBEAiB+zugK0WO7rmMCDxjO\n" \
"ig4kkvocIw1I21oV9btCs79j6AIgfdh9ssnstpVncHwHvteGCscId77lWvShjCsU\n" \
"DhCTJGA=\n" \
"-----END CERTIFICATE-----\n"
 
 
/* ================= Private Key ================= */
 
#define PRIVATE_KEY \
"-----BEGIN EC PRIVATE KEY-----\n" \
"MHcCAQEEIJ5J12YmRrEzGKrkX08/QEPpJTgE74VIqs9rh6mtPf4poAoGCCqGSM49\n" \
"AwEHoUQDQgAESWDPF4vazgl6YgLSffZiueByYKr9fBEIwauLVk0NueFHI1od9yVH\n" \
"CEQZYqI/rhtO6rcddvnIHR1Dman7m8duHQ==\n" \
"-----END EC PRIVATE KEY-----\n"

/* Compatibility symbols used by pnet_mqtt.c tls_credential_add() calls.
 * All three credentials are always registered because this is a mutual TLS
 * (mTLS) setup: ROOT_CA verifies the broker, CLIENT_CERT + PRIVATE_KEY
 * identify the device to the broker.
 */
static const unsigned char ca_pem[]            = ROOT_CA;
static const unsigned int  ca_pem_len          = sizeof(ca_pem);

static const unsigned char client_cert_pem[]   = CLIENT_CERT;
static const unsigned int  client_cert_pem_len = sizeof(client_cert_pem);

static const unsigned char private_key_pem[]   = PRIVATE_KEY;
static const unsigned int  private_key_pem_len = sizeof(private_key_pem);

#endif /* CA_CERT_H */
