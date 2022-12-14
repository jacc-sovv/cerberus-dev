# ++
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.
#
# Module Name:
#
#	GccArmCortexM7.cmake
#
# Abstract:
#
#	GCC ARM Cortex-M7 Toolchain file
#
# --

set(CMAKE_SYSTEM_NAME Generic)
SET(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_SYSTEM_PROCESSOR Cortex-M7)

set(CERBERUS_MCU_FLAGS "-mcpu=cortex-m7")
set(CERBERUS_MCU_FLAGS "${CERBERUS_MCU_FLAGS} -mfloat-abi=hard")
set(CERBERUS_MCU_FLAGS "${CERBERUS_MCU_FLAGS} -mfpu=fpv4-sp-d16")
set(CERBERUS_MCU_FLAGS "${CERBERUS_MCU_FLAGS} -mthumb")

include(${CMAKE_CURRENT_LIST_DIR}/GccArmNoneEabi.cmake)
