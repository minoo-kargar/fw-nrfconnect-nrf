#
# Copyright (c) 2018 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#

cmake_minimum_required(VERSION 3.8.2)

#include(../../../cmake/boilerplate.cmake NO_POLICY_SCOPE)
include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
project(NONE)

# NORDIC SDK APP START
target_sources(app PRIVATE src/main.c)
target_include_directories(app PRIVATE ../common)
# NORDIC SDK APP END

if (NOT TEST_SEND_INTERVAL_MS)
  add_definitions(-DCONFIG_TEST_SEND_INTERVAL_MS=60000)
else()
  add_definitions(-DCONFIG_TEST_SEND_INTERVAL_MS=${TEST_SEND_INTERVAL_MS})
endif()

if (NOT TEST_PCK_ITT_MS)
  add_definitions(-DCONFIG_TEST_PCK_ITT_MS=5000)
else()
  add_definitions(-DCONFIG_TEST_PCK_ITT_MS=${TEST_PCK_ITT_MS})
endif()

if (NOT TEST_PCK_NR_IN_BURST)
  add_definitions(-DCONFIG_TEST_PCK_NR_IN_BURST=1)
else()
  add_definitions(-DCONFIG_TEST_PCK_NR_IN_BURST=${TEST_PCK_NR_IN_BURST})
endif()

if (NOT TEST_MAX_MSG_LEN_BYTE)
  add_definitions(-DCONFIG_TEST_MAX_MSG_LEN_BYTE=20)
else()
  add_definitions(-DCONFIG_TEST_MAX_MSG_LEN_BYTE=${TEST_MAX_MSG_LEN_BYTE})
endif()

if (NOT TEST_DURATION)
  add_definitions(-DCONFIG_TEST_DURATION=60)
else()
  add_definitions(-DCONFIG_TEST_DURATION=${TEST_DURATION})
endif()

if (NOT TEST_MQTT_QOS)
  add_definitions(-DCONFIG_TEST_MQTT_QOS=0)
else()
  add_definitions(-DCONFIG_TEST_MQTT_QOS=${TEST_MQTT_QOS})
endif()

