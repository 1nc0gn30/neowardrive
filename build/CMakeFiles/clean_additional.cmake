# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "")
  file(REMOVE_RECURSE
  "app.js.S"
  "bootloader/bootloader.bin"
  "bootloader/bootloader.elf"
  "bootloader/bootloader.map"
  "config/sdkconfig.cmake"
  "config/sdkconfig.h"
  "esp-idf/mbedtls/x509_crt_bundle"
  "flash_app_args"
  "flash_bootloader_args"
  "flash_project_args"
  "flasher_args.json"
  "flasher_args.json.in"
  "glitch.css.S"
  "index.html.S"
  "ldgen_libraries"
  "ldgen_libraries.in"
  "neo_wardrive.bin"
  "neo_wardrive.map"
  "project_elf_src_esp32s2.c"
  "x509_crt_bundle.S"
  )
endif()
