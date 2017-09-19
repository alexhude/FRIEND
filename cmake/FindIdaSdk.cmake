# Copyright 2011-2016 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Locates and configures the IDA Pro SDK.
#
# Defines the following variables:
#
#   IdaSdk_INCLUDE_DIRS - Include directories for the IDA Pro SDK.
#   IdaSdk_PLATFORM - IDA SDK platform, one of __LINUX__, __NT__ or __MAC__.
#
# Example:
#
#   find_package(IdaSdk REQUIRED)
#   include_directories(${IdaSdk_INCLUDE_DIRS})
#
#   # Builds target plugin32.plx
#   add_ida_plugin(plugin32 myplugin.cc)
#   # Builds targets plugin.plx and plugin.plx64
#   add_ida_plugin(plugin EA64 myplugin.cc)
#   # Builds target plugin64.plx64
#   add_ida_plugin(plugin64 NOEA32 EA64 myplugin.cc)
#
#   Builds targets ldr.llx and ldr64.llx64
#   add_ida_loader(ldr EA64 myloader.cc)

include(CMakeParseArguments)

set(IdaSdk_DIR ${PROJECT_SOURCE_DIR}/idasdk CACHE STRING "Path to IDA SDK")
set(IdaSdk_INCLUDE_DIRS ${IdaSdk_DIR}/include)

# Define some platform specific variables for later use.
if(APPLE)
  set(IdaSdk_PLATFORM __MAC__)
  if(USE_IDA6_SDK)
    set(_plx .pmc)
    set(_plx64 .pmc64)
    set(_llx .lmc)
    set(_llx64 64.lmc64)  # An additional "64"
  else()
    set(_plx .dylib)
    set(_llx .dylib)
    set(_plx64 64.dylib)  # An additional "64"
    set(_llx64 64.dylib)  # An additional "64"
  endif()
elseif(UNIX)
  set(IdaSdk_PLATFORM __LINUX__)
  if(USE_IDA6_SDK)
    set(_plx .plx)
    set(_plx64 .plx64)
    set(_llx .llx)
    set(_llx64 64.llx64)  # An additional "64"
  else()
    set(_plx .so)
    set(_llx .so)
    set(_plx64 64.so)     # An additional "64"
    set(_llx64 64.so)     # An additional "64"
  endif()
elseif(WIN32)
  set(IdaSdk_PLATFORM __NT__)
  if(USE_IDA6_SDK)
    set(_plx .plw)
    set(_plx64 .p64)
    set(_llx .ldw)
    set(_llx64 64.l64)    # An additional "64"
  else()
    set(_plx .dll)
    set(_llx .dll)
    set(_plx64 64.dll)    # An additional "64"
    set(_llx64 64.dll)    # An additional "64"
  endif()
else()
  message(FATAL_ERROR "Unsupported system type: ${CMAKE_SYSTEM_NAME}")
endif()

if(USE_IDA6_SDK)
  set(_osx_arch "$(ARCHS_STANDARD_32_BIT)")
  set(_lib_path "x86")
else()
  set(_osx_arch "$(ARCHS_STANDARD)")
  set(_lib_path "x64")
endif()

function(_ida_plugin name ea64 link_script)  # ARGN contains sources
  # Define a module with the specified sources.
  add_library(${name} MODULE ${ARGN})

  # Build for 64bit
  if(NOT USE_IDA6_SDK)
    target_compile_definitions(${name} PUBLIC __X64__)
  endif()

  # Support for 64-bit addresses.
  if(ea64)
    target_compile_definitions(${name} PUBLIC __EA64__)
  endif()

  # Add the necessary __IDP__ define and allow to use "dangerous" and standard
  # file functions.
  target_compile_definitions(${name} PUBLIC
                             ${IdaSdk_PLATFORM}
                             __IDP__
                             USE_DANGEROUS_FUNCTIONS
                             USE_STANDARD_FILE_FUNCTIONS)

  set_target_properties(${name} PROPERTIES PREFIX "" SUFFIX "")
  if(UNIX)
    if(USE_IDA6_SDK)
      # Always build a 32-bit executable and use the linker script needed for IDA.
      target_compile_options(${name} PUBLIC -m32)
    endif()

    if(APPLE)
      set(CMAKE_OSX_ARCHITECTURES ${_osx_arch})
      set(dynamic_lookup -Wl,-flat_namespace
                         -Wl,-undefined,warning
                         -Wl,-exported_symbol,_PLUGIN)
    else()
      set(script_flag -Wl,--version-script ${IdaSdk_DIR}/${link_script})
    endif()

    if(USE_IDA6_SDK)
      target_link_libraries(${name} -m32 ${script_flag} ${dynamic_lookup})
    else()
      target_link_libraries(${name} ${script_flag} ${dynamic_lookup})
    endif()

    # For qrefcnt_obj_t in ida.hpp
    target_compile_options(${name} PUBLIC -Wno-non-virtual-dtor)
  elseif(WIN32)
    if(ea64)
      set(IdaSdk_LIBRARY ${IdaSdk_DIR}/lib/${_lib_path}_win_vc_64/ida.lib)
    else()
      set(IdaSdk_LIBRARY ${IdaSdk_DIR}/lib/${_lib_path}_win_vc_32/ida.lib)
    endif()
    target_link_libraries(${name} ${IdaSdk_LIBRARY})
  endif()
endfunction()

function(add_ida_plugin name)
  set(options NOEA32 EA64)
  cmake_parse_arguments(add_ida_plugin "${options}" "" "" ${ARGN})

  if(NOT DEFINED(add_ida_plugin_NOEA32))
    _ida_plugin(${name}${_plx} FALSE plugins/plugin.script
                ${add_ida_plugin_UNPARSED_ARGUMENTS})
  endif()
  if(add_ida_plugin_EA64)
    _ida_plugin(${name}${_plx64} TRUE plugins/plugin.script
                ${add_ida_plugin_UNPARSED_ARGUMENTS})
  endif()
endfunction()

function(add_ida_loader name)
  set(options NOEA32 EA64)
  cmake_parse_arguments(add_ida_loader "${options}" "" "" ${ARGN})

  if(NOT DEFINED(add_ida_loader_NOEA32))
    _ida_plugin(${name}${_llx} FALSE ldr/ldr.script
                ${add_ida_loader_UNPARSED_ARGUMENTS})
  endif()
  if(add_ida_loader_EA64)
    _ida_plugin(${name}${_llx64} TRUE ldr/ldr.script
                ${add_ida_loader_UNPARSED_ARGUMENTS})
  endif()
endfunction()

