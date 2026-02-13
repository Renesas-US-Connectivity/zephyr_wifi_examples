#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/socket_poll.h>

LOG_MODULE_REGISTER(mqtt_test, LOG_LEVEL_DBG);

#define MQTT_CLIENTID "--->>> zephyr MQTT client <<<---"
// #define MQTT_BROKER_ADDR "3.122.182.249"
#define MQTT_BROKER_ADDR "2000::f415:6fad:6044:a8"
#define MQTT_BROKER_PORT 1884

static struct mqtt_client client;
static struct sockaddr_storage broker;
static uint8_t rx_buffer[256];
static uint8_t tx_buffer[256];

static bool can_publish = false;

/* Thread for processing mqtt incoming packets */
#define CONFIG_MQTT_THREAD_STACK_SIZE 3200
static void mqtt_comm_thread(void *arg1, void *arg2, void *arg3);
#define MQTT_THREAD_PRIORITY 5
K_THREAD_DEFINE(mqtt_thread, K_THREAD_STACK_LEN(CONFIG_MQTT_THREAD_STACK_SIZE),
                mqtt_comm_thread, &client, NULL, NULL, MQTT_THREAD_PRIORITY, 0,
                0);

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

  ret = mqtt_publish(&client, &param);
  LOG_ERR("TEST MQTT PUBLISH: %d (%s)", ret, strerror(-ret));
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
      LOG_ERR("Socket type: %d == %d\n", type, SOCK_STREAM);

      getsockopt(c->transport.tcp.sock, SOL_SOCKET, SO_PROTOCOL, &type, &len);
      LOG_ERR("Socket protocol: %d == %d\n", type, IPPROTO_TCP);

      topics.topic.utf8 = topic_str;
      topics.topic.size = strlen(topic_str);
      topics.qos = MQTT_QOS_1_AT_LEAST_ONCE;

      list.list = &topics;
      list.list_count = 1;
      list.message_id = 1;

      ret = mqtt_subscribe(c, &list);

      LOG_ERR("TEST MQTT SUB: %d (%s)", ret, strerror(-ret));

    } else {
      LOG_INF("MQTT connect failed (%d)\n", evt->result);
    }
    break;
  case MQTT_EVT_DISCONNECT:
    LOG_INF("TEST MQTT disconnected\n");
    can_publish = false;
    break;
  case MQTT_EVT_SUBACK:
    LOG_ERR("TEST MQTT SUBACK: message_id: %d", evt->param.puback.message_id);
    can_publish = true;
    break;
  case MQTT_EVT_PINGRESP:
    LOG_DBG("PONG\\");
    break;
  case MQTT_EVT_PUBLISH:
    LOG_ERR("TEST MQTT RECEIVED PUBLISH");
    handle_published_message(c, &evt->param.publish);
    break;
  default:
    LOG_ERR("TEST Unknown MQTT event: %d", evt->type);
    break;
  }
}

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

    LOG_INF("socket: %d", fds.fd);

    rc = zsock_poll(&fds, 1, -1);
    switch (rc) {
    case 1:
      if (fds.revents & ZSOCK_POLLNVAL) {
        LOG_INF("Socked %d closed", fds.fd);
        return;
      }

      if (fds.revents & ZSOCK_POLLERR) {
        LOG_ERR("Socket error 0x%08x", fds.revents);
      }

      if (fds.revents & ZSOCK_POLLIN) {
        rc = mqtt_input(client);
        if (rc < 0) {
          LOG_ERR("Failed to read MQTT input: %d, %s", rc, strerror(-rc));
        }
      }

      if (fds.revents & ZSOCK_POLLHUP) {
        LOG_ERR("0x%08x: Closing the socket: %d", fds.revents, fds.fd);
      }

      break;
    case 0: /* poll tout */
      break;
    default:
      LOG_ERR("poll err: %d (%d: %s)", rc, errno, strerror(errno));
      k_sleep(K_MSEC(3000));
      break;
    }
  }
}

int connect_to_broker(void) {
  int ret;
  struct sockaddr_in *broker4 = (struct sockaddr_in *)&broker;
  struct sockaddr_in6 *broker6 = (struct sockaddr_in6 *)&broker;
  char addr_str[INET6_ADDRSTRLEN];

  /* Clear the structure completely */
  memset(&broker, 0, sizeof(broker));

  /* Try to parse as IPv6 first if it contains a colon */
  if (strchr(MQTT_BROKER_ADDR, ':')) {
    ret = zsock_inet_pton(AF_INET6, MQTT_BROKER_ADDR, &broker6->sin6_addr);
    if (ret == 1) {
      broker6->sin6_family = AF_INET6;
      broker6->sin6_port = htons(MQTT_BROKER_PORT);
      zsock_inet_ntop(AF_INET6, &broker6->sin6_addr, addr_str,
                      sizeof(addr_str));
      LOG_INF("Using IPv6 broker address: %s", addr_str);
    } else {
      LOG_ERR("Failed to parse IPv6 address: %s", MQTT_BROKER_ADDR);
      return -EINVAL;
    }
  } else {
    /* Try to parse as IPv4 */
    ret = zsock_inet_pton(AF_INET, MQTT_BROKER_ADDR, &broker4->sin_addr);
    if (ret == 1) {
      broker4->sin_family = AF_INET;
      broker4->sin_port = htons(MQTT_BROKER_PORT);
      LOG_INF("Using IPv4 broker address: %s", MQTT_BROKER_ADDR);
    } else {
      LOG_ERR("Invalid IPv4 address format: %s", MQTT_BROKER_ADDR);
      return -EINVAL;
    }
  }

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

  ret = mqtt_connect(&client);
  if (ret) {
    LOG_ERR("mqtt_connect failed: %d (%s)\n", ret, strerror(-ret));
    return ret;
  }

  LOG_ERR("TEST MQTT CONNECTED (sock: %d): %d (%s)", client.transport.tcp.sock,
          ret, strerror(-ret));

  return 0;
}
