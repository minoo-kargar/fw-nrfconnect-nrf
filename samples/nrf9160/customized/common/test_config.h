#ifndef TEST_CONFIG_H_
#define TEST_CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif
#include <stdio.h>
#include <string.h>

#include <net/coap.h>
#include <net/mqtt.h>
#include <net/socket.h>


#define TEST_CONFIG_SEND_INTERVAL_MS K_MSEC(60000) // 1 minutes in between burst of packets
#define TEST_CONFIG_PCK_ITT_MS       K_MSEC(5000)  // 5 seconds inter-transmission time
#define TEST_CONFIG_PCK_NR_IN_BURST  1             // Number of packets that should be sent every TEST_CONFIG_SEND_INTERVAL_MS
#define TEST_CONFIG_MAX_MSG_LEN_BYTE 10
#define TEST_CONFIG_NR_OF_TEST_RUN   5


/* CoAP config parameters */
#define TEST_CONFIG_COAP_TYPE   COAP_TYPE_CON
#define TEST_CONFIG_COAP_METHOD COAP_METHOD_GET

/* MQTT config parameters */
#define TEST_CONFIG_MQTT_QOS MQTT_QOS_1_AT_LEAST_ONCE

#endif // TEST_CONFIG_H_