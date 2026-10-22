cmake_minimum_required(VERSION 3.13.1)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(app)

target_sources(app PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/src/tests_iface.c
)


include(${CMAKE_CURRENT_SOURCE_DIR}/config/CMakeLists.txt)
