cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr)
project(pnet_shell)

target_sources(app PRIVATE src/pnet_mqtt.c)