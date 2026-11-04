# Copyright (c) 2026, Oracle and/or its affiliates.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2.0,
# as published by the Free Software Foundation.
#
# This program is designed to work with certain software (including
# but not limited to OpenSSL) that is licensed under separate terms,
# as designated in a particular file or component or in included license
# documentation.  The authors of MySQL hereby grant you an additional
# permission to link the program and your derivative works with the
# separately licensed software that they have either included with
# the program or referenced in the documentation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License, version 2.0, for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA

## The platform and the ABI affecting flags an out of tree extension must be
## built with. Include after all top level definitions and flags are set.

MACRO(MYSQL_SDK_NORMALIZE_PLATFORM OUT)
  STRING(TOLOWER "${CMAKE_SYSTEM_NAME}" SDK_OS)
  IF(SDK_OS STREQUAL "darwin")
    SET(SDK_OS "macos")
  ENDIF()
  STRING(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" SDK_ARCH)
  IF(SDK_ARCH MATCHES "^(amd64|x64|x86_64)$")
    SET(SDK_ARCH "x86_64")
  ELSEIF(SDK_ARCH MATCHES "^(arm64|aarch64)$")
    SET(SDK_ARCH "aarch64")
  ENDIF()
  SET(${OUT} "${SDK_OS}-${SDK_ARCH}")
ENDMACRO()

# Warnings, optimization, debug info and LTO do not change the ABI.
FUNCTION(MYSQL_SDK_FILTER_CXXFLAGS OUT)
  SET(KEPT)
  FOREACH(FLAG ${ARGN})
    IF(FLAG MATCHES "^[-/][DU]." OR
       FLAG MATCHES "^-std=" OR FLAG MATCHES "^/std:" OR
       FLAG MATCHES "^-ftls-model=" OR
       FLAG MATCHES "^-f(no-)?(rtti|exceptions|PIC|pic)$" OR
       FLAG MATCHES "^-f(un)?signed-char$" OR
       FLAG MATCHES "^-m" OR
       FLAG MATCHES "^/(EH|GR|MD|MT|Zc:)")
      LIST(APPEND KEPT "${FLAG}")
    ENDIF()
  ENDFOREACH()
  LIST(REMOVE_DUPLICATES KEPT)
  STRING(REPLACE ";" " " KEPT "${KEPT}")
  SET(${OUT} "${KEPT}" PARENT_SCOPE)
ENDFUNCTION()

FUNCTION(MYSQL_SDK_FILTER_LDFLAGS OUT)
  SET(KEPT)
  FOREACH(FLAG ${ARGN})
    IF(FLAG MATCHES "^-Wl," OR FLAG MATCHES "^-fuse-ld=" OR
       FLAG MATCHES "^-m" OR FLAG MATCHES "^/MACHINE:")
      LIST(APPEND KEPT "${FLAG}")
    ENDIF()
  ENDFOREACH()
  LIST(REMOVE_DUPLICATES KEPT)
  STRING(REPLACE ";" " " KEPT "${KEPT}")
  SET(${OUT} "${KEPT}" PARENT_SCOPE)
ENDFUNCTION()

MACRO(MYSQL_SDK_C_ESCAPE VAR)
  STRING(REPLACE "\\" "\\\\" ${VAR} "${${VAR}}")
  STRING(REPLACE "\"" "\\\"" ${VAR} "${${VAR}}")
ENDMACRO()

MACRO(MYSQL_COMPUTE_SDK_IDENTITY)
  MYSQL_SDK_NORMALIZE_PLATFORM(MYSQL_SDK_PLATFORM)
  STRING(TOUPPER "${CMAKE_BUILD_TYPE}" SDK_BUILD_TYPE)

  IF(DEFINED CMAKE_CXX_EXTENSIONS AND NOT CMAKE_CXX_EXTENSIONS)
    SET(SDK_STD "${CMAKE_CXX${CMAKE_CXX_STANDARD}_STANDARD_COMPILE_OPTION}")
  ELSE()
    SET(SDK_STD "${CMAKE_CXX${CMAKE_CXX_STANDARD}_EXTENSION_COMPILE_OPTION}")
  ENDIF()

  # A package is always a loadable module, see plugin.cmake.
  GET_DIRECTORY_PROPERTY(SDK_DEFS
    DIRECTORY ${CMAKE_SOURCE_DIR} COMPILE_DEFINITIONS)
  GET_DIRECTORY_PROPERTY(SDK_OPTS
    DIRECTORY ${CMAKE_SOURCE_DIR} COMPILE_OPTIONS)
  SET(SDK_CXXFLAGS)
  FOREACH(DEF ${SDK_DEFS} MYSQL_DYNAMIC_PLUGIN)
    LIST(APPEND SDK_CXXFLAGS "-D${DEF}")
  ENDFOREACH()
  SEPARATE_ARGUMENTS(SDK_FLAGS NATIVE_COMMAND
    "${SDK_STD} ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${SDK_BUILD_TYPE}}")
  LIST(APPEND SDK_CXXFLAGS ${SDK_OPTS} ${SDK_FLAGS})
  MYSQL_SDK_FILTER_CXXFLAGS(MYSQL_SDK_CXXFLAGS ${SDK_CXXFLAGS})

  SEPARATE_ARGUMENTS(SDK_LINK NATIVE_COMMAND
    "${CMAKE_MODULE_LINKER_FLAGS} ${CMAKE_MODULE_LINKER_FLAGS_${SDK_BUILD_TYPE}}")
  MYSQL_SDK_FILTER_LDFLAGS(MYSQL_SDK_LDFLAGS ${SDK_LINK})

  MESSAGE(STATUS "SDK platform ${MYSQL_SDK_PLATFORM}")
  MESSAGE(STATUS "SDK cxxflags ${MYSQL_SDK_CXXFLAGS}")
  MESSAGE(STATUS "SDK ldflags ${MYSQL_SDK_LDFLAGS}")

  SET(MYSQL_SDK_CXXFLAGS_ESCAPED "${MYSQL_SDK_CXXFLAGS}")
  SET(MYSQL_SDK_LDFLAGS_ESCAPED "${MYSQL_SDK_LDFLAGS}")
  MYSQL_SDK_C_ESCAPE(MYSQL_SDK_CXXFLAGS_ESCAPED)
  MYSQL_SDK_C_ESCAPE(MYSQL_SDK_LDFLAGS_ESCAPED)
  CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/include/mysql_sdk_build.h.in
                 ${CMAKE_BINARY_DIR}/include/mysql_sdk_build.h)
ENDMACRO()
