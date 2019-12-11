#
# Copyright (c) 2018 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#

cmake_minimum_required(VERSION 3.8.2)

#include(../../../cmake/boilerplate.cmake NO_POLICY_SCOPE)
include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
project(NONE)

add_definitions(-DCONFIG_TEST_SEND_INTERVAL_MS=60000 -DCONFIG_TEST_PCK_ITT_MS=5000 -DCONFIG_TEST_PCK_NR_IN_BURST=1 -DCONFIG_TEST_MAX_MSG_LEN_BYTE=20 -DCONFIG_TEST_DURATION=60 -DTEST_MQTT_QOS=0)

# NORDIC SDK APP START
target_sources(app PRIVATE src/main.c)
target_include_directories(app PRIVATE ../common)
# NORDIC SDK APP END
