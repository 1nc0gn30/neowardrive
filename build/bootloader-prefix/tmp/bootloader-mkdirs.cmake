# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/neo/esp-idf/components/bootloader/subproject"
  "/home/neo/esp/neo_wardrive/build/bootloader"
  "/home/neo/esp/neo_wardrive/build/bootloader-prefix"
  "/home/neo/esp/neo_wardrive/build/bootloader-prefix/tmp"
  "/home/neo/esp/neo_wardrive/build/bootloader-prefix/src/bootloader-stamp"
  "/home/neo/esp/neo_wardrive/build/bootloader-prefix/src"
  "/home/neo/esp/neo_wardrive/build/bootloader-prefix/src/bootloader-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/neo/esp/neo_wardrive/build/bootloader-prefix/src/bootloader-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/neo/esp/neo_wardrive/build/bootloader-prefix/src/bootloader-stamp${cfgdir}") # cfgdir has leading slash
endif()
