# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.13)

project(vector_pr)

set(CMAKE_BUILD_TYPE Debug)

add_executable(vector_pr ${CMAKE_CURRENT_LIST_DIR}/vector_pr.cpp)

# Import Microsoft SEAL
find_package(SEAL 4.0.0 EXACT REQUIRED)

target_link_libraries(vector_pr PRIVATE SEAL::seal_shared)