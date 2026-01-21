/*
 * Copyright (c) 2023 Lucas Dietrich <ld.adecy@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "creds/creds.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "net_sample_common.h"
#include <zephyr/data/json.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/dns_resolve.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/random/random.h>

#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/wifi_mgmt.h>

#include <zephyr/logging/log.h>

#if defined(CONFIG_MBEDTLS_MEMORY_DEBUG)
#include <mbedtls/memory_buffer_alloc.h>
#endif

LOG_MODULE_REGISTER(aws, LOG_LEVEL_DBG);

#define SNTP_SERVER "0.pool.ntp.org"

#define AWS_BROKER_PORT CONFIG_AWS_MQTT_PORT

#define MQTT_BUFFER_SIZE 256u
#define APP_BUFFER_SIZE 4096u

#define MAX_RETRIES 10u
#define BACKOFF_EXP_BASE_MS 1000u
#define BACKOFF_EXP_MAX_MS 60000u
#define BACKOFF_CONST_MS 5000u

static struct sockaddr_in aws_broker;

static uint8_t rx_buffer[MQTT_BUFFER_SIZE];
static uint8_t tx_buffer[MQTT_BUFFER_SIZE];
static uint8_t buffer[APP_BUFFER_SIZE]; /* Shared between published and received
                                           messages */

static struct mqtt_client client_ctx;

static const char mqtt_client_name[] = CONFIG_AWS_THING_NAME;

static uint32_t messages_received_counter;
static bool do_publish;   /* Trigger client to publish */
static bool do_subscribe; /* Trigger client to subscribe */

#if (CONFIG_AWS_MQTT_PORT == 443 && !defined(CONFIG_MQTT_LIB_WEBSOCKET))
static const char *const alpn_list[] = {"x-amzn-mqtt-ca"};
#endif

#define TLS_TAG_DEVICE_CERTIFICATE 1
#define TLS_TAG_AWS_CA_CERTIFICATE 2

static const sec_tag_t sec_tls_tags[] = {
    TLS_TAG_DEVICE_CERTIFICATE,
    TLS_TAG_AWS_CA_CERTIFICATE,
};

int wifi_ps_set(struct net_if *iface, struct wifi_ps_params *p);
int wifi_ps_state_set(struct net_if *iface, bool enable);
void gpio_trigger_wakeup(const struct device *gpio_dev);
void set_low_power_mode(struct net_if *iface, uint16_t listen_interval,
                        uint32_t timeout_ms);
bool erpc_crc_check();
int gpio_wakeup_init(const struct device **gpio_dev);

bool is_ncp_ready = true;
struct k_mutex erpc_mutex;
bool is_subscribed = false;
const struct device *g_gpio_wakeup_dev;

void recv_upon_ps_mode_wake(struct mqtt_client *client) {
  int rc;
  k_mutex_lock(&erpc_mutex, K_FOREVER);
  rc = mqtt_input(client);
  if (rc < 0) {
    LOG_ERR("Failed to read MQTT input: %d, %s", rc, strerror(-rc));
    k_mutex_lock(&erpc_mutex, K_FOREVER);
    enable_ps_mode();
    k_mutex_unlock(&erpc_mutex);
    k_sleep(K_SECONDS(6));
  }

  uint32_t start_time = k_uptime_get_32();
  while (k_uptime_get_32() - start_time < 5000) {
    k_msleep(100);
  }

  // enable_ps_mode();
  //   is_ncp_ready = false;
  k_mutex_unlock(&erpc_mutex);
}

static int setup_credentials(void) {
  int ret;

  ret = tls_credential_add(TLS_TAG_DEVICE_CERTIFICATE,
                           TLS_CREDENTIAL_SERVER_CERTIFICATE, public_cert,
                           public_cert_len);
  if (ret < 0) {
    LOG_ERR("Failed to add device certificate: %d", ret);
    return ret;
  }

  ret =
      tls_credential_add(TLS_TAG_DEVICE_CERTIFICATE, TLS_CREDENTIAL_PRIVATE_KEY,
                         private_key, private_key_len);
  if (ret < 0) {
    LOG_ERR("Failed to add device private key: %d", ret);
    return ret;
  }

  ret = tls_credential_add(TLS_TAG_AWS_CA_CERTIFICATE,
                           TLS_CREDENTIAL_CA_CERTIFICATE, ca_cert, ca_cert_len);
  if (ret < 0) {
    LOG_ERR("Failed to add CA certificate: %d", ret);
    return ret;
  }

  return 0;
}
static int subscribe_topic(void) {
  int ret;
  struct mqtt_topic topics[] = {{
      .topic = {.utf8 = CONFIG_AWS_SUBSCRIBE_TOPIC,
                .size = strlen(CONFIG_AWS_SUBSCRIBE_TOPIC)},
      .qos = CONFIG_AWS_QOS,
  }};
  const struct mqtt_subscription_list sub_list = {
      .list = topics,
      .list_count = ARRAY_SIZE(topics),
      .message_id = 1u,
  };

  LOG_INF("Subscribing to %hu topic(s)", sub_list.list_count);

  ret = mqtt_subscribe(&client_ctx, &sub_list);
  if (ret != 0) {
    LOG_ERR("Failed to subscribe to topics: %d", ret);
  }

  return ret;
}

static int publish_message(const char *topic, size_t topic_len,
                           uint8_t *payload, size_t payload_len) {
  static uint32_t message_id = 1u;

  int ret;
  struct mqtt_publish_param msg;

  msg.retain_flag = 0u;
  msg.dup_flag = 0u;
  msg.message.topic.topic.utf8 = topic;
  msg.message.topic.topic.size = topic_len;
  msg.message.topic.qos = CONFIG_AWS_QOS;
  msg.message.payload.data = payload;
  msg.message.payload.len = payload_len;
  msg.message_id = message_id++;

  ret = mqtt_publish(&client_ctx, &msg);
  if (ret != 0) {
    LOG_ERR("Failed to publish message: %d", ret);
  }

  LOG_INF("PUBLISHED on topic \"%s\" [ id: %u qos: %u ], payload: %u B", topic,
          msg.message_id, msg.message.topic.qos, payload_len);
  LOG_HEXDUMP_DBG(payload, payload_len, "Published payload:");

  return ret;
}

static ssize_t handle_published_message(const struct mqtt_publish_param *pub) {
  int ret;
  size_t received = 0u;
  const size_t message_size = pub->message.payload.len;
  const bool discarded = message_size > APP_BUFFER_SIZE;

  LOG_INF("RECEIVED on topic \"%s\" [ id: %u qos: %u ] payload: %u / %u B",
          (const char *)pub->message.topic.topic.utf8, pub->message_id,
          pub->message.topic.qos, message_size, APP_BUFFER_SIZE);

  while (received < message_size) {
    uint8_t *p = discarded ? buffer : &buffer[received];

    ret = mqtt_read_publish_payload_blocking(&client_ctx, p, APP_BUFFER_SIZE);
    if (ret < 0) {
      return ret;
    }

    received += ret;
  }

  if (!discarded) {
    LOG_HEXDUMP_DBG(buffer, MIN(message_size, 256u), "Received payload:");
  }

  /* Send ACK */
  switch (pub->message.topic.qos) {
  case MQTT_QOS_1_AT_LEAST_ONCE: {
    struct mqtt_puback_param puback;

    puback.message_id = pub->message_id;
    mqtt_publish_qos1_ack(&client_ctx, &puback);
  } break;
  case MQTT_QOS_2_EXACTLY_ONCE: /* unhandled (not supported by AWS) */
  case MQTT_QOS_0_AT_MOST_ONCE: /* nothing to do */
  default:
    break;
  }

  return discarded ? -ENOMEM : received;
}

const char *mqtt_evt_type_to_str(enum mqtt_evt_type type) {
  static const char *const types[] = {
      "CONNACK", "DISCONNECT", "PUBLISH", "PUBACK",   "PUBREC",
      "PUBREL",  "PUBCOMP",    "SUBACK",  "UNSUBACK", "PINGRESP",
  };

  return (type < ARRAY_SIZE(types)) ? types[type] : "<unknown>";
}

static void mqtt_event_cb(struct mqtt_client *client,
                          const struct mqtt_evt *evt) {
  LOG_DBG("MQTT event: %s [%u] result: %d", mqtt_evt_type_to_str(evt->type),
          evt->type, evt->result);

  switch (evt->type) {
  case MQTT_EVT_CONNACK: {
    do_subscribe = true;
  } break;

  case MQTT_EVT_PUBLISH: {
    const struct mqtt_publish_param *pub = &evt->param.publish;

    handle_published_message(pub);
    messages_received_counter++;
#if !defined(CONFIG_AWS_TEST_SUITE_RECV_QOS1)
    do_publish = true;
#endif
  } break;

  case MQTT_EVT_SUBACK: {
    is_subscribed = true;
#if !defined(CONFIG_AWS_TEST_SUITE_RECV_QOS1)
    do_publish = true;
#endif
  } break;

  case MQTT_EVT_PUBACK:
  case MQTT_EVT_DISCONNECT:
  case MQTT_EVT_PUBREC:
  case MQTT_EVT_PUBREL:
  case MQTT_EVT_PUBCOMP:
  case MQTT_EVT_PINGRESP:
  case MQTT_EVT_UNSUBACK:
  default:
    break;
  }
}

static void aws_client_setup(void) {
  mqtt_client_init(&client_ctx);

  client_ctx.broker = &aws_broker;
  client_ctx.evt_cb = mqtt_event_cb;

  client_ctx.client_id.utf8 = (uint8_t *)mqtt_client_name;
  client_ctx.client_id.size = sizeof(mqtt_client_name) - 1;
  client_ctx.password = NULL;
  client_ctx.user_name = NULL;

  client_ctx.keepalive = CONFIG_MQTT_KEEPALIVE;

  client_ctx.protocol_version = MQTT_VERSION_3_1_1;

  client_ctx.rx_buf = rx_buffer;
  client_ctx.rx_buf_size = MQTT_BUFFER_SIZE;
  client_ctx.tx_buf = tx_buffer;
  client_ctx.tx_buf_size = MQTT_BUFFER_SIZE;

  /* setup TLS */
  client_ctx.transport.type = MQTT_TRANSPORT_SECURE;
  struct mqtt_sec_config *const tls_config = &client_ctx.transport.tls.config;

  tls_config->peer_verify = TLS_PEER_VERIFY_OPTIONAL;
  tls_config->cipher_list = NULL;
  tls_config->sec_tag_list = sec_tls_tags;
  tls_config->sec_tag_count = ARRAY_SIZE(sec_tls_tags);
  tls_config->hostname = CONFIG_AWS_ENDPOINT;
  tls_config->cert_nocopy = TLS_CERT_NOCOPY_NONE;
#if (CONFIG_AWS_MQTT_PORT == 443 && !defined(CONFIG_MQTT_LIB_WEBSOCKET))
  tls_config->alpn_protocol_name_list = alpn_list;
  tls_config->alpn_protocol_name_count = ARRAY_SIZE(alpn_list);
#endif
}

struct backoff_context {
  uint16_t retries_count;
  uint16_t max_retries;

#if defined(CONFIG_AWS_EXPONENTIAL_BACKOFF)
  uint32_t attempt_max_backoff; /* ms */
  uint32_t max_backoff;         /* ms */
#endif
};

static void backoff_context_init(struct backoff_context *bo) {
  __ASSERT_NO_MSG(bo != NULL);

  bo->retries_count = 0u;
  bo->max_retries = MAX_RETRIES;

#if defined(CONFIG_AWS_EXPONENTIAL_BACKOFF)
  bo->attempt_max_backoff = BACKOFF_EXP_BASE_MS;
  bo->max_backoff = BACKOFF_EXP_MAX_MS;
#endif
}

/* https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/ */
static void backoff_get_next(struct backoff_context *bo,
                             uint32_t *next_backoff_ms) {
  __ASSERT_NO_MSG(bo != NULL);
  __ASSERT_NO_MSG(next_backoff_ms != NULL);

#if defined(CONFIG_AWS_EXPONENTIAL_BACKOFF)
  if (bo->retries_count <= bo->max_retries) {
    *next_backoff_ms = sys_rand32_get() % (bo->attempt_max_backoff + 1u);

    /* Calculate max backoff for the next attempt (~ 2**attempt) */
    bo->attempt_max_backoff =
        MIN(bo->attempt_max_backoff * 2u, bo->max_backoff);
    bo->retries_count++;
  }
#else
  *next_backoff_ms = BACKOFF_CONST_MS;
#endif
}

static int aws_client_try_connect(void) {
  int ret;
  uint32_t backoff_ms;
  struct backoff_context bo;

  backoff_context_init(&bo);

  while (bo.retries_count <= bo.max_retries) {
    ret = mqtt_connect(&client_ctx);
    if (ret == 0) {
      goto exit;
    }

    backoff_get_next(&bo, &backoff_ms);

    LOG_ERR("Failed to connect: %d backoff delay: %u ms", ret, backoff_ms);
    k_msleep(backoff_ms);
  }

exit:
  return ret;
}

struct publish_payload {
  uint32_t counter;
};

static const struct json_obj_descr json_descr[] = {
    JSON_OBJ_DESCR_PRIM(struct publish_payload, counter, JSON_TOK_NUMBER),
};

static int publish(void) {
  struct publish_payload pl = {.counter = messages_received_counter};
  if (!erpc_crc_check())
    disable_ps_mode();

  while (!erpc_crc_check())
    ;

  json_obj_encode_buf(json_descr, ARRAY_SIZE(json_descr), &pl, buffer,
                      sizeof(buffer));

  return publish_message(CONFIG_AWS_PUBLISH_TOPIC,
                         strlen(CONFIG_AWS_PUBLISH_TOPIC), buffer,
                         strlen(buffer));
  enable_ps_mode();
  k_sleep(K_MSEC(2000));
}

void aws_client_loop(void) {
  int rc;
  int timeout;
  struct pollfd fds;

  aws_client_setup();

  rc = aws_client_try_connect();
  if (rc != 0) {
    goto cleanup;
  }

  fds.fd = client_ctx.transport.tcp.sock;
  fds.events = POLLIN;

  for (;;) {
    timeout = mqtt_keepalive_time_left(&client_ctx);

    if (is_ncp_ready) {
      k_mutex_lock(&erpc_mutex, K_FOREVER);
      LOG_INF("NCP Polling\n");
      rc = poll(&fds, 1, timeout);
      k_mutex_unlock(&erpc_mutex);
    } else {
      printf("is_ncp_ready: %d\n", is_ncp_ready);
      while (erpc_wifi_transport_slave_ready() != 1)
        ;
      printf("NCP ready\n");
      while (!erpc_crc_check())
        ;
      recv_upon_ps_mode_wake(&client_ctx);
      k_sleep(K_MSEC(2000));
      continue;
    }

    if (rc >= 0) {
      if (fds.revents & POLLIN) {
        k_mutex_lock(&erpc_mutex, K_FOREVER);
        rc = mqtt_input(&client_ctx);
        k_mutex_unlock(&erpc_mutex);
        if (rc != 0) {
          LOG_ERR("Failed to read MQTT input: %d", rc);
          continue;
        }
      }

      if (fds.revents & (POLLHUP | POLLERR)) {
        LOG_ERR("Socket closed/error");
        break;
      }
#if 0
      rc = mqtt_live(&client_ctx);
      if ((rc != 0) && (rc != -EAGAIN)) {
        LOG_ERR("Failed to live MQTT: %d", rc);
        break;
      }
#endif
    } else {
      LOG_ERR("poll failed: %d", rc);
      k_sleep(K_MSEC(3000));
      break;
    }

    if (do_publish) {
      do_publish = false;
      publish();
    }

    if (do_subscribe) {
      do_subscribe = false;
      subscribe_topic();
    }
    if (is_subscribed) {
      k_mutex_lock(&erpc_mutex, K_FOREVER);
      enable_ps_mode();
      k_mutex_unlock(&erpc_mutex);
      is_subscribed = false;
      k_sleep(K_SECONDS(6));
    }
  }

cleanup:
  mqtt_disconnect(&client_ctx, NULL);

  close(fds.fd);
  fds.fd = -1;
}

static int resolve_broker_addr(struct sockaddr_in *broker) {
  int ret;
  struct addrinfo *ai = NULL;

  const struct addrinfo hints = {
      .ai_family = AF_INET,
      .ai_socktype = SOCK_STREAM,
      .ai_protocol = 0,
  };
  char port_string[6] = {0};
  char addr_str[INET_ADDRSTRLEN];

  sprintf(port_string, sizeof(port_string), "%d", AWS_BROKER_PORT);

  LOG_INF("DNS resolve start");
  LOG_INF("  Host : %s", CONFIG_AWS_ENDPOINT);
  LOG_INF("  Port : %s", port_string);

  do {
    ret = getaddrinfo(CONFIG_AWS_ENDPOINT, port_string, &hints, &ai);

    if (ret != 0) {
      LOG_ERR("getaddrinfo() failed");
      LOG_ERR("  ret        = %d", ret);
      LOG_ERR("  gai_strerr = %s", gai_strerror(ret));
      LOG_ERR("  errno      = %d", errno);

      k_msleep(2000);
    }
  } while (ret != 0);

  LOG_INF("DNS resolve success");

  memcpy(broker, ai->ai_addr,
         MIN(ai->ai_addrlen, sizeof(struct sockaddr_storage)));
  broker->sin_port = htons(AWS_BROKER_PORT);
  inet_ntop(AF_INET, &broker->sin_addr, addr_str, sizeof(addr_str));

  LOG_INF("Resolved broker address: %s:%u", addr_str, AWS_BROKER_PORT);

  freeaddrinfo(ai);

  return ret;

  /*hard-coded DNS IP*/
  // 	 memset(broker, 0, sizeof(*broker));

  //     broker->sin_family = AF_INET;
  //     broker->sin_port = htons(8883);

  //     inet_pton(AF_INET, "15.164.18.28", &broker->sin_addr);

  // 	LOG_INF("Using hardcoded AWS IP: 15.164.18.28:8883");

  // return 0;
}

/* Wi-Fi network configuration */
/* Wi-Fi network configuration */
#define WIFI_SSID "ITP-FF"
#define WIFI_PSK "WiFiNetge@r@1"

/* Test message configuration */
#define TX_MESSAGE_LEN_MAX 32
#define RX_MESSAGE_LEN_MAX 32

/* Wi-Fi connection events */
#define WIFI_EVENT_CONNECT_SUCCESS BIT(0)
#define WIFI_EVENT_CONNECT_FAILED BIT(1)
#define WIFI_EVENT_ALL (WIFI_EVENT_CONNECT_SUCCESS | WIFI_EVENT_CONNECT_FAILED)
#define NET_EVENT_ALL (NET_EVENT_IPV4_ADDR_ADD | NET_EVENT_IPV4_DHCP_BOUND)

static void print_wifi_status(struct wifi_iface_status *status);

static struct net_mgmt_event_callback cb;
static struct net_mgmt_event_callback cb1;

K_EVENT_DEFINE(connect_event);
K_EVENT_DEFINE(net_event);

static void wifi_event_handler(struct net_mgmt_event_callback *cb,
                               uint64_t mgmt_event, struct net_if *iface) {
  const struct wifi_status *status = (const struct wifi_status *)cb->info;

  LOG_INF("Wi-Fi event - layer: %llx code: %llx cmd: %llx status: %d",
          NET_MGMT_GET_LAYER(mgmt_event), NET_MGMT_GET_LAYER_CODE(mgmt_event),
          NET_MGMT_GET_COMMAND(mgmt_event), status->status);

  switch (mgmt_event) {
  case NET_EVENT_WIFI_CONNECT_RESULT:
    if (status->status == 0) {
      LOG_INF("Connected to AP!");
      k_event_set(&connect_event, WIFI_EVENT_CONNECT_SUCCESS);
    } else {
      LOG_INF("Failed to connect to AP!");
      k_event_set(&connect_event, WIFI_EVENT_CONNECT_FAILED);
    }
    break;
  default:
    break;
  }
}

static void net_event_handler(struct net_mgmt_event_callback *cb,
                              uint64_t mgmt_event, struct net_if *iface) {
  const struct wifi_status *status = (const struct wifi_status *)cb->info;

  LOG_INF("NET event - layer: %llx code: %llx cmd: %llx status: %d",
          NET_MGMT_GET_LAYER(mgmt_event), NET_MGMT_GET_LAYER_CODE(mgmt_event),
          NET_MGMT_GET_COMMAND(mgmt_event), status->status);

  switch (mgmt_event) {
  case NET_EVENT_IPV4_ADDR_ADD:
    k_event_set(&net_event, NET_EVENT_IPV4_ADDR_ADD);
    LOG_INF("IPv4 address added");
    break;
  case NET_EVENT_IPV4_DHCP_BOUND:
    k_event_set(&net_event, NET_EVENT_IPV4_DHCP_BOUND);
    LOG_INF("DHCP bound - we have an IP address!");
    break;
  default:
    break;
  }
}

static void dhcp_event_handler(struct net_mgmt_event_callback *cb,
                               uint32_t mgmt_event, struct net_if *iface) {
  if (mgmt_event == NET_EVENT_IPV4_DHCP_BOUND) {
    LOG_INF("DHCP bound - we have an IP address!");

    // Get the assigned IP
    struct in_addr *addr =
        net_if_ipv4_get_global_addr(iface, NET_ADDR_PREFERRED);
    if (addr) {
      char ip_str[NET_IPV4_ADDR_LEN];
      net_addr_ntop(AF_INET, addr, ip_str, sizeof(ip_str));
      LOG_INF("IP Address: %s", ip_str);
    }
  }
}

extern int connect_to_broker(void);
int main(void) {
  int fd;
  int bytes_sent;
  int bytes_recvd;
  struct net_if *iface;
  struct in_addr *if_addr;
  struct wifi_connect_req_params config = {0};
  struct wifi_iface_status status = {0};
  struct wifi_version version = {0};
  const struct device *gpio_wakeup_dev = NULL;
  uint32_t events;

  char if_addr_s[NET_IPV4_ADDR_LEN];

  printk("AWS-MQTT TEST\n");
  LOG_INF("Starting AWS station MQTT client...");
  k_msleep(3000);
  iface = net_if_get_wifi_sta();
  if (iface == NULL) {
    LOG_INF("Cannot find the Wi-Fi interface");
    return 0;
  }

  if (gpio_wakeup_init(&gpio_wakeup_dev) != 0) {
    LOG_WRN("Failed to initialize GPIO wakeup pin, continuing without it");
  }
  g_gpio_wakeup_dev = gpio_wakeup_dev;

  LOG_INF("Setting Listen interval...\n");
  struct wifi_ps_params p = {0};
  p.type = WIFI_PS_PARAM_LISTEN_INTERVAL;
  p.listen_interval = 20;
  wifi_ps_set(iface, &p);

  net_mgmt_init_event_callback(&cb, wifi_event_handler,
                               NET_EVENT_WIFI_CONNECT_RESULT);
  net_mgmt_add_event_callback(&cb);

  net_mgmt_init_event_callback(&cb1, net_event_handler,
                               NET_EVENT_IPV4_ADDR_ADD |
                                   NET_EVENT_IPV4_DHCP_BOUND);
  net_mgmt_add_event_callback(&cb1);

  printk("callback registered\n");
  if (net_mgmt(NET_REQUEST_WIFI_VERSION, iface, &version, sizeof(version)) ==
      0) {
    LOG_INF("Wi-Fi Driver Version: %s", version.drv_version);
    LOG_INF("Wi-Fi Firmware Version: %s", version.fw_version);
  }
  printk("version get success\n");

  config.ssid = (const uint8_t *)WIFI_SSID;
  config.ssid_length = strlen(WIFI_SSID);
  config.psk = (const uint8_t *)WIFI_PSK;
  config.psk_length = strlen(WIFI_PSK);
  config.security = WIFI_SECURITY_TYPE_PSK;
  config.channel = WIFI_CHANNEL_ANY;
  config.band = WIFI_FREQ_BAND_2_4_GHZ;

  do {
    LOG_INF("Connecting to network (SSID: %s)", config.ssid);

    if (net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &config,
                 sizeof(struct wifi_connect_req_params))) {
      LOG_INF("Wi-Fi connect request failed");
      return 0;
    }

    events = k_event_wait(&connect_event, WIFI_EVENT_ALL, true, K_FOREVER);
    if (events == WIFI_EVENT_CONNECT_SUCCESS) {
      LOG_INF("Joined network!");
      break;
    }
  } while (1);

  do {
    events = k_event_wait(&net_event, NET_EVENT_ALL, true, K_FOREVER);
    if (events & NET_EVENT_IPV4_DHCP_BOUND) {
      LOG_INF("DHCP lease received!\n");
      break;
    }
  } while (1);

#if defined(CONFIG_SHIELD_RENESAS_QCIOT_RRQ61051EVZ_PMOD)
  do {
    LOG_INF("Waiting for IP address to be assigned...\n");

    if_addr = net_if_ipv4_get_global_addr(iface, NET_ADDR_PREFERRED);

    if (if_addr) {
      net_addr_ntop(AF_INET, if_addr->s4_addr, if_addr_s, sizeof(if_addr_s));
      LOG_INF("Address: %s", if_addr_s);
    } else {
      k_msleep(1000);
    }
  } while (if_addr == NULL);
#else
  k_msleep(3000);
#endif

  setup_credentials();

  printk("waiting to wifi success\n");
  // wait_for_network();

  printk("connection to wifi success\n");
  for (;;) {
    resolve_broker_addr(&aws_broker);

    aws_client_loop();

#if defined(CONFIG_MBEDTLS_MEMORY_DEBUG)
    size_t cur_used, cur_blocks, max_used, max_blocks;

    mbedtls_memory_buffer_alloc_cur_get(&cur_used, &cur_blocks);
    mbedtls_memory_buffer_alloc_max_get(&max_used, &max_blocks);
    LOG_INF("mbedTLS heap usage: MAX %u/%u (%u) CUR %u (%u)", max_used,
            CONFIG_MBEDTLS_HEAP_SIZE, max_blocks, cur_used, cur_blocks);
#endif

    k_sleep(K_SECONDS(1));
  }

  return 0;
}
