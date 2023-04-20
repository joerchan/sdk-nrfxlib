if (CONFIG_PSA_CORE_BUILTIN)
  add_subdirectory(mbedcrypto)
endif()

if (CONFIG_PSA_CORE_OBERON)
  add_subdirectory(nrf_oberon)
endif()
