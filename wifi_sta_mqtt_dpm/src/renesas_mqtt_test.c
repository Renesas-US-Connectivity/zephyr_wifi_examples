#include <stdbool.h>
#include <string.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/socket_poll.h>
#include <zephyr/net/wifi_mgmt.h>

LOG_MODULE_REGISTER(mqtt_test, LOG_LEVEL_DBG);

#define MQTT_CLIENTID "--->>> zephyr MQTT client <<<---"
// #define MQTT_BROKER_ADDR "3.122.182.249"
#define MQTT_BROKER_ADDR "192.168.31.224"
#define MQTT_BROKER_PORT 1884
#define ENABLE_DPM 1
extern const struct device *g_gpio_wakeup_dev;
extern struct k_mutex erpc_mutex;

static struct mqtt_client client;
static struct sockaddr_storage broker;
static uint8_t rx_buffer[256];
static uint8_t tx_buffer[256];

static bool can_publish = false;
static bool is_ncp_ready = true;

/* Thread for processing mqtt incoming packets */
#define CONFIG_MQTT_THREAD_STACK_SIZE 3200
static void mqtt_comm_thread(void *arg1, void *arg2, void *arg3);
#define MQTT_THREAD_PRIORITY 5
K_THREAD_DEFINE(mqtt_thread, K_THREAD_STACK_LEN(CONFIG_MQTT_THREAD_STACK_SIZE),
                mqtt_comm_thread, &client, NULL, NULL, MQTT_THREAD_PRIORITY, 0,
                0);

int wifi_ps_set(struct net_if *iface, struct wifi_ps_params *p);
int wifi_ps_state_set(struct net_if *iface, bool enable);
void gpio_trigger_wakeup(const struct device *gpio_dev);
void set_low_power_mode(struct net_if *iface, uint16_t listen_interval,
                        uint32_t timeout_ms);

int is_subscribed = 0;
int is_mqtt_connected = 0;

bool erpc_crc_check() {
  struct wifi_version version = {0};

  if (net_mgmt(NET_REQUEST_WIFI_VERSION, net_if_get_wifi_sta(), &version,
               sizeof(version)) == 0) {
    if (strlen((char *)version.drv_version) > 0) {
      LOG_INF("Wi-Fi Driver Version: %s", version.drv_version);
      return true;
    }
  }

  return false;
}

void enable_ps_mode() {
  LOG_INF("Set Power save mode ON\n");
  set_low_power_mode(net_if_get_wifi_sta(), 20, 1000);
  /* wait for device to sleep */
  is_ncp_ready = false;
}

void disable_ps_mode() {
  LOG_INF("Restoring Active Mode for ACK...");

  gpio_trigger_wakeup(g_gpio_wakeup_dev);
  /* wait for device to wake up*/
  k_sleep(K_SECONDS(15));
}

static void mqtt_publish_data(void) {
  int ret;

  const uint8_t *topic_str = "zephyr/mqtt/test/data";
  struct mqtt_publish_param param = {0};
  uint8_t data[] = "The quick brown fox jumps over the lazy dog.";

  if (!can_publish) {
    LOG_ERR("Can't publish yet");
    return;
  }

  param.message.topic.qos = MQTT_QOS_0_AT_MOST_ONCE;
  param.message.topic.topic.utf8 = topic_str;
  param.message.topic.topic.size = strlen(topic_str);

  param.message.payload.data = data;
  param.message.payload.len = sizeof(data);

  param.message_id = 666;
  param.dup_flag = 0;
  param.retain_flag = 0;

  LOG_HEXDUMP_DBG(param.message.payload.data, param.message.payload.len,
                  "pub message");

  /* Disable power save before sending */
  LOG_INF("Restoring Active Mode...");
  k_mutex_lock(&erpc_mutex, K_FOREVER);
  wifi_ps_state_set(net_if_get_default(), false);
  k_mutex_unlock(&erpc_mutex);

  k_mutex_lock(&erpc_mutex, K_FOREVER);
  ret = mqtt_publish(&client, &param);
  k_mutex_unlock(&erpc_mutex);
  LOG_ERR("TEST MQTT PUBLISH: %d (%s)", ret, strerror(-ret));

  /* Re-enable power save after sending */
  k_mutex_lock(&erpc_mutex, K_FOREVER);
  wifi_ps_state_set(net_if_get_default(), true);
  k_mutex_unlock(&erpc_mutex);
  k_msleep(100);
}

static ssize_t handle_published_message(struct mqtt_client *client,
                                        const struct mqtt_publish_param *pub) {
  int ret;
  size_t received = 0u;
  size_t message_len = pub->message.payload.len;
  static uint8_t payload_buf[1024];

  LOG_INF("RECEIVED on topic \"%.*s\" [ id: %u qos: %u ] payload: %u B",
          pub->message.topic.topic.size,
          (const char *)pub->message.topic.topic.utf8, pub->message_id,
          pub->message.topic.qos, message_len);

  do {
    ret = mqtt_read_publish_payload_blocking(client, &payload_buf[received],
                                             message_len - received);
    if (ret == 0) {
      break;
    }

    if (ret == -EAGAIN) {
      continue;
    }

    received += ret;
  } while (received < message_len);

  if (received != message_len) {
    LOG_ERR("Received data size mismatch %d != %d", received, message_len);

    return -ESPIPE;
  }

  LOG_HEXDUMP_DBG(payload_buf, received, "pub rec:");

  /* Send ACK */
  switch (pub->message.topic.qos) {
  case MQTT_QOS_0_AT_MOST_ONCE:
    break;
  case MQTT_QOS_1_AT_LEAST_ONCE:
    mqtt_publish_qos1_ack(client, &(struct mqtt_puback_param){pub->message_id});

    break;
  case MQTT_QOS_2_EXACTLY_ONCE:
    mqtt_publish_qos2_receive(client,
                              &(struct mqtt_pubrec_param){pub->message_id});

    break;
  default:
    break;
  }

  if (strncmp(payload_buf, "pubme", received) == 0) {
    LOG_ERR("Try publish data");
    mqtt_publish_data();
  }

  return received;
}

static void mqtt_evt_handler(struct mqtt_client *const c,
                             const struct mqtt_evt *evt) {
  int ret;
  struct mqtt_subscription_list list;
  struct mqtt_topic topics;
  uint8_t *topic_str = "zephyr/mqtt/test";

  switch (evt->type) {
  case MQTT_EVT_CONNACK:
    if (evt->result == 0) {

      LOG_INF("TEST MQTT connected\n");

      int type;
      socklen_t len = sizeof(type);
      getsockopt(c->transport.tcp.sock, SOL_SOCKET, SO_TYPE, &type, &len);
      LOG_INF("Socket type: %d == %d\n", type, SOCK_STREAM);

      getsockopt(c->transport.tcp.sock, SOL_SOCKET, SO_PROTOCOL, &type, &len);
      LOG_INF("Socket protocol: %d == %d\n", type, IPPROTO_TCP);

      topics.topic.utf8 = topic_str;
      topics.topic.size = strlen(topic_str);
      topics.qos = MQTT_QOS_1_AT_LEAST_ONCE;

      list.list = &topics;
      list.list_count = 1;
      list.message_id = 1;
      is_mqtt_connected = 1;
      ret = mqtt_subscribe(c, &list);

      LOG_INF("TEST MQTT Smqtt_subscribeUB: %d (%s)", ret, strerror(-ret));

    } else {
      LOG_ERR("MQTT connect failed (%d)\n", evt->result);
    }
    break;
  case MQTT_EVT_DISCONNECT:
    LOG_INF("TEST MQTT disconnected\n");
    can_publish = false;
    break;
  case MQTT_EVT_SUBACK:
    LOG_INF("TEST MQTT SUBACK: message_id: %d", evt->param.puback.message_id);
#ifdef ENABLE_DPM
    LOG_INF("Entering DPM power save mode");
#endif
    can_publish = true;
    is_subscribed = 1;
    break;
  case MQTT_EVT_PINGRESP:
    LOG_DBG("PONG\\");
    break;
  case MQTT_EVT_PUBLISH:
    LOG_INF("TEST MQTT RECEIVED PUBLISH");
    handle_published_message(c, &evt->param.publish);
    break;
  default:
    LOG_ERR("TEST Unknown MQTT event: %d", evt->type);
    break;
  }
}

void recv_upon_ps_mode_wake(struct mqtt_client *client) {
  int rc;
  k_mutex_lock(&erpc_mutex, K_FOREVER);
  rc = mqtt_input(client);
  if (rc < 0) {
    LOG_ERR("Failed to read MQTT input: %d, %s", rc, strerror(-rc));
  }

  uint32_t start_time = k_uptime_get_32();
  while (k_uptime_get_32() - start_time < 5000) {
    k_msleep(100);
  }

  // enable_ps_mode();
  //   is_ncp_ready = false;
  k_mutex_unlock(&erpc_mutex);
}

extern int erpc_wifi_transport_slave_ready(void);
static void mqtt_comm_thread(void *arg1, void *arg2, void *arg3) {
  struct mqtt_client *client = arg1;
  struct zsock_pollfd fds = {0};
  int rc;

  LOG_ERR("MQTT THREAD START");

  for (;;) {

    fds.fd = client->transport.tcp.sock;
    fds.events = ZSOCK_POLLIN;
    fds.revents = 0;

    if (client->transport.tcp.sock <= 0) {
      k_sleep(K_MSEC(3000));
      continue;
    }

    printf("is_subscribed: %d\n", is_subscribed);
    if (is_subscribed) {
      enable_ps_mode();
      k_sleep(K_SECONDS(6));
      is_subscribed = 0;
    }

    if (is_ncp_ready) {
      k_mutex_lock(&erpc_mutex, K_FOREVER);
      LOG_INF("NCP Polling\n");
      rc = zsock_poll(&fds, 1, -1);
      k_mutex_unlock(&erpc_mutex);
    } else {
      printf("is_ncp_ready: %d\n", is_ncp_ready);
      while (erpc_wifi_transport_slave_ready() != 1) {
        // printf("NCP not ready\n");
        //  k_sleep(K_SECONDS(1));
      }
      printf("NCP ready\n");
      while (!erpc_crc_check()) {
        printf("ERPC CRC check failed\n");
        k_sleep(K_SECONDS(1));
      }
      recv_upon_ps_mode_wake(client);
      k_sleep(K_MSEC(2000));
      // is_ncp_ready = true;
      continue;
    }

    switch (rc) {
    case 0:
#if 0
      k_mutex_lock(&erpc_mutex, K_FOREVER);
      rc = mqtt_input(client);
      k_mutex_unlock(&erpc_mutex);
      if (rc < 0) {
        LOG_ERR("Failed to read MQTT input: %d, %s", rc, strerror(-rc));
      }
#endif
      break;
    case 1:
      if (fds.revents & ZSOCK_POLLNVAL) {
        LOG_INF("Socked %d closed", fds.fd);
        return;
      }

      if (fds.revents & ZSOCK_POLLERR) {
        LOG_ERR("Socket error 0x%08x", fds.revents);
      }

      if (fds.revents & ZSOCK_POLLIN) {
        k_mutex_lock(&erpc_mutex, K_FOREVER);
        rc = mqtt_input(client);
        k_mutex_unlock(&erpc_mutex);
        if (rc < 0) {
          LOG_ERR("Failed to read MQTT input: %d, %s", rc, strerror(-rc));
        }
      }

      if (fds.revents & ZSOCK_POLLHUP) {
        LOG_ERR("0x%08x: Closing the socket: %d", fds.revents, fds.fd);
      }

      break;

    default:
      LOG_ERR("poll err: %d (%d: %s)", rc, errno, strerror(errno));
      k_sleep(K_MSEC(3000));
      break;
    }
    // enable_ps_mode();
  }
}

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
    LOG_ERR("mqtt_connect failed: %d (%s)\n", ret, strerror(-ret));
    return ret;
  }

  LOG_ERR("TEST MQTT CONNECTED (sock: %d): %d (%s)", client.transport.tcp.sock,
          ret, strerror(-ret));

  return 0;
}
