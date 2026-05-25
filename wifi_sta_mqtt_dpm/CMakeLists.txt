cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr)
project(wifi_sta_tcp_client)

target_sources(app PRIVATE 
	src/main.c
	src/renesas_mqtt_test.c
)
