#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/wifi_mgmt.h>

LOG_MODULE_REGISTER(mqtt_test, LOG_LEVEL_DBG);

#define MQTT_CLIENTID "--->>> zephyr MQTT client <<<---"
#define MQTT_BROKER_ADDR "192.168.28.165"
#define MQTT_BROKER_PORT 1883

#define MQTT_LOOP_TOPIC "rrq_sub"
#define MQTT_PUB_QOS MQTT_QOS_0_AT_MOST_ONCE
#define DPM_LISTEN_INTERVAL 10
#define DPM_TIMEOUT_MS 100
#define MQTT_WAKE_SETTLE_MS 1000
#define PUBLISH_LOOP_DELAY_MS 10000

extern const struct device *g_gpio_wakeup_dev;
extern struct k_mutex erpc_mutex;

static struct mqtt_client client;
static struct sockaddr_storage broker;
static uint8_t rx_buffer[256];
static uint8_t tx_buffer[256];

static bool can_publish;
static bool in_dpm;
static bool publish_loop_enabled;
static bool first_publish_done;
static bool dpm_profile_configured;

int wifi_ps_state_set(struct net_if *iface, bool enable);
void gpio_trigger_wakeup(const struct device *gpio_dev);
void set_low_power_mode(struct net_if *iface, uint16_t listen_interval,
                        uint32_t timeout_ms);

int is_subscribed = 0;
int is_mqtt_connected = 0;

static void enter_dpm_mode(void) {
  if (!is_mqtt_connected) {
    return;
  }

  if (!dpm_profile_configured) {
    set_low_power_mode(net_if_get_wifi_sta(), DPM_LISTEN_INTERVAL,
                       DPM_TIMEOUT_MS);
    dpm_profile_configured = true;
  } else {
    wifi_ps_state_set(net_if_get_wifi_sta(), true);
  }

  in_dpm = true;
  LOG_INF("DPM enabled");
}

static void wake_for_mqtt_io(const char *reason) {
  LOG_INF("Wake reason: %s", reason);

  if (g_gpio_wakeup_dev != NULL) {
    gpio_trigger_wakeup(g_gpio_wakeup_dev);
  }

  wifi_ps_state_set(net_if_get_wifi_sta(), false);

  k_msleep(MQTT_WAKE_SETTLE_MS);

  in_dpm = false;
}

static int mqtt_publish_data(const uint8_t *payload, size_t payload_len) {
  int ret;
  struct mqtt_publish_param param = {0};

  if (!can_publish) {
    LOG_WRN("Skipping publish because client is not ready");
    return -EAGAIN;
  }

  param.message.topic.qos = MQTT_PUB_QOS;
  param.message.topic.topic.utf8 = (uint8_t *)MQTT_LOOP_TOPIC;
  param.message.topic.topic.size = strlen(MQTT_LOOP_TOPIC);
  param.message.payload.data = (uint8_t *)payload;
  param.message.payload.len = payload_len;
  param.message_id = 666;
  param.dup_flag = 0;
  param.retain_flag = 0;

  LOG_INF("Publishing %d bytes to topic %s", payload_len, MQTT_LOOP_TOPIC);
  k_mutex_lock(&erpc_mutex, K_FOREVER);
  ret = mqtt_publish(&client, &param);
  k_mutex_unlock(&erpc_mutex);

  if (ret) {
    LOG_ERR("mqtt_publish failed: %d (%s)", ret, strerror(-ret));
  }

  return ret;
}

static ssize_t handle_published_message(struct mqtt_client *mqtt,
                                        const struct mqtt_publish_param *pub) {
  int ret;
  size_t received = 0u;
  size_t message_len = pub->message.payload.len;
  static uint8_t payload_buf[1024];

  LOG_INF("Received topic %.*s payload %u B", pub->message.topic.topic.size,
          (const char *)pub->message.topic.topic.utf8, message_len);

  do {
    ret = mqtt_read_publish_payload_blocking(mqtt, &payload_buf[received],
                                             message_len - received);
    if (ret == 0) {
      break;
    }

    if (ret == -EAGAIN) {
      continue;
    }

    if (ret < 0) {
      LOG_ERR("mqtt_read_publish_payload_blocking failed: %d", ret);
      return ret;
    }

    received += ret;
  } while (received < message_len);

  if (received != message_len) {
    LOG_ERR("Received data size mismatch %d != %d", received, message_len);
    return -ESPIPE;
  }

  LOG_HEXDUMP_INF(payload_buf, received, "RX payload");

  switch (pub->message.topic.qos) {
  case MQTT_QOS_0_AT_MOST_ONCE:
    break;
  case MQTT_QOS_1_AT_LEAST_ONCE:
    mqtt_publish_qos1_ack(mqtt, &(struct mqtt_puback_param){pub->message_id});
    break;
  case MQTT_QOS_2_EXACTLY_ONCE:
    mqtt_publish_qos2_receive(mqtt,
                              &(struct mqtt_pubrec_param){pub->message_id});
    break;
  default:
    break;
  }

  return received;
}

static void mqtt_evt_handler(struct mqtt_client *const c,
                             const struct mqtt_evt *evt) {
  int ret;
  struct mqtt_subscription_list list;
  struct mqtt_topic topics;

  switch (evt->type) {
  case MQTT_EVT_CONNACK:
    if (evt->result == 0) {
      topics.topic.utf8 = (uint8_t *)MQTT_LOOP_TOPIC;
      topics.topic.size = strlen(MQTT_LOOP_TOPIC);
      topics.qos = MQTT_QOS_0_AT_MOST_ONCE;

      list.list = &topics;
      list.list_count = 1;
      list.message_id = 1;

      is_mqtt_connected = 1;
      ret = mqtt_subscribe(c, &list);
      LOG_INF("mqtt_subscribe: %d (%s)", ret, ret ? strerror(-ret) : "ok");
    } else {
      LOG_ERR("MQTT connect failed (%d)", evt->result);
    }
    break;

  case MQTT_EVT_DISCONNECT:
    LOG_INF("MQTT disconnected");
    can_publish = false;
    is_mqtt_connected = 0;
    is_subscribed = 0;
    publish_loop_enabled = false;
    first_publish_done = false;
    dpm_profile_configured = false;
    break;

  case MQTT_EVT_SUBACK:
    LOG_INF("MQTT SUBACK message_id: %d", evt->param.suback.message_id);
    can_publish = true;
    is_subscribed = 1;
    publish_loop_enabled = true;
    first_publish_done = false;
    break;

  case MQTT_EVT_PINGRESP:
    LOG_DBG("PONG");
    break;

  case MQTT_EVT_PUBLISH:
    LOG_INF("MQTT PUBLISH event");
    handle_published_message(c, &evt->param.publish);
    break;

  default:
    LOG_DBG("Unhandled MQTT event: %d", evt->type);
    break;
  }
}

static int mqtt_drain_input(struct mqtt_client *mqtt) {
  int rc;

  k_mutex_lock(&erpc_mutex, K_FOREVER);
  rc = mqtt_input(mqtt);
  k_mutex_unlock(&erpc_mutex);

  if (rc == -EAGAIN || rc == 0) {
    return 0;
  }

  if (rc < 0) {
    LOG_ERR("mqtt_input failed: %d (%s)", rc, strerror(-rc));
    return rc;
  }

  return 0;
}

static void mqtt_comm_thread(void *arg1, void *arg2, void *arg3) {
  struct mqtt_client *mqtt = arg1;
  static const uint8_t hello_payload[] = "hello";

  ARG_UNUSED(arg2);
  ARG_UNUSED(arg3);

  LOG_INF("MQTT loop thread started");

  for (;;) {
    if (mqtt->transport.tcp.sock <= 0) {
      k_sleep(K_MSEC(1000));
      continue;
    }

    if (!publish_loop_enabled) {
      mqtt_drain_input(mqtt);
      k_sleep(K_MSEC(100));
      continue;
    }

    if (!first_publish_done) {
      wake_for_mqtt_io("initial publish after SUBACK");
      mqtt_publish_data(hello_payload, sizeof(hello_payload) - 1);
      enter_dpm_mode();
      first_publish_done = true;
      continue;
    }

    k_sleep(K_MSEC(PUBLISH_LOOP_DELAY_MS));
    wake_for_mqtt_io("periodic publish");
    mqtt_publish_data(hello_payload, sizeof(hello_payload) - 1);
    enter_dpm_mode();
  }
}

#define CONFIG_MQTT_THREAD_STACK_SIZE 3200
#define MQTT_THREAD_PRIORITY 5
K_THREAD_DEFINE(mqtt_thread, K_THREAD_STACK_LEN(CONFIG_MQTT_THREAD_STACK_SIZE),
                mqtt_comm_thread, &client, NULL, NULL, MQTT_THREAD_PRIORITY, 0,
                0);

int connect_to_broker(void) {
  struct sockaddr_in *broker4 = (struct sockaddr_in *)&broker;

  broker4->sin_family = AF_INET;
  broker4->sin_port = htons(MQTT_BROKER_PORT);
  inet_pton(AF_INET, MQTT_BROKER_ADDR, &broker4->sin_addr);

  mqtt_client_init(&client);

  client.broker = &broker;
  client.evt_cb = mqtt_evt_handler;
  client.client_id.utf8 = (uint8_t *)MQTT_CLIENTID;
  client.client_id.size = strlen(MQTT_CLIENTID);
  client.keepalive = 1000;
  client.protocol_version = MQTT_VERSION_3_1_1;

  client.rx_buf = rx_buffer;
  client.rx_buf_size = sizeof(rx_buffer);
  client.tx_buf = tx_buffer;
  client.tx_buf_size = sizeof(tx_buffer);
  client.transport.type = MQTT_TRANSPORT_NON_SECURE;

  k_mutex_lock(&erpc_mutex, K_FOREVER);
  int ret = mqtt_connect(&client);
  k_mutex_unlock(&erpc_mutex);

  if (ret) {
    LOG_ERR("mqtt_connect failed: %d (%s)", ret, strerror(-ret));
    return ret;
  }

  LOG_INF("MQTT connected socket=%d", client.transport.tcp.sock);
  return 0;
}
