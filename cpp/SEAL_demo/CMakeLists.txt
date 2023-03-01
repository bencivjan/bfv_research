# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.13)

project(bfv_demo)

add_executable(bfv_playground ${CMAKE_CURRENT_LIST_DIR}/bfv_playground.cpp)

# Import Microsoft SEAL
find_package(SEAL 4.0.0 EXACT REQUIRED)

target_link_libraries(bfv_playground PRIVATE SEAL::seal_shared)