target_sources_ifdef(CONFIG_DT_HAS_ZEPHYR_CDC_NCM_ETHERNET_ENABLED app PRIVATE
	${CMAKE_CURRENT_LIST_DIR}/src/usbeth.c
	${CMAKE_CURRENT_LIST_DIR}/src/utils_iface_eth.c
)

target_sources_ifdef(CONFIG_SPI app PRIVATE
	${CMAKE_CURRENT_LIST_DIR}/src/utils_iface_wifi.c
)

target_sources_ifdef(CONFIG_BOARD_NATIVE_SIM app PRIVATE
	${CMAKE_CURRENT_LIST_DIR}/src/utils_iface_eth.c
)

target_sources(app PRIVATE
	${CMAKE_CURRENT_LIST_DIR}/src/utils_tcp.c
	${CMAKE_CURRENT_LIST_DIR}/src/utils_iconfig.c
	${CMAKE_CURRENT_LIST_DIR}/src/utils_http.c
	${CMAKE_CURRENT_LIST_DIR}/src/utils_dns.c
)

target_include_directories(app PRIVATE ${CMAKE_CURRENT_LIST_DIR}/src)

include(${ZEPHYR_BASE}/samples/subsys/usb/common/common.cmake)