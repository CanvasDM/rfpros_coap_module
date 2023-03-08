if(CONFIG_LCZ_COAP_TELEMETRY)
    zephyr_include_directories(include)
    zephyr_sources(
        lcz_coap_telemetry/src/lcz_coap_telemetry.c
    )    
endif()
    
if(CONFIG_LCZ_COAP_SOCK)
    zephyr_include_directories(${CMAKE_SOURCE_DIR}/lcz_coap_sock/include)
    zephyr_sources(
        lcz_coap_sock/src/lcz_coap_sock.c
    )
endif()
