cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr)
project(pnet_multi_thread_https_zephyr_http)

target_sources(app PRIVATE
	src/pnet_multi_threaded.c
	src/https_get.c
)