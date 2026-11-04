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

## Installs the server headers and a CMake package, so plugins and components
## can be built against an installed server without its source tree.
## Include after MYSQL_COMPUTE_SDK_IDENTITY().

OPTION(WITH_PLUGIN_SDK "Install the plugin SDK" ON)

SET(INSTALL_SDK_INCLUDEDIR "${INSTALL_INCLUDEDIR}/server")
SET(INSTALL_SDK_CMAKEDIR "${INSTALL_LIBDIR}/cmake/MySQLSDK")

MACRO(MYSQL_INSTALL_PLUGIN_SDK)
  IF(WITH_PLUGIN_SDK)
    # The tree layout is kept, since server headers include each other by
    # paths such as "sql/handler.h".
    FOREACH(DIR include sql libs sql-common vector-common)
      INSTALL(DIRECTORY ${CMAKE_SOURCE_DIR}/${DIR}/
        DESTINATION ${INSTALL_SDK_INCLUDEDIR}/${DIR}
        COMPONENT PluginSDK
        FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp")
    ENDFOREACH()

    INSTALL(DIRECTORY ${CMAKE_BINARY_DIR}/include/
      DESTINATION ${INSTALL_SDK_INCLUDEDIR}/include
      COMPONENT PluginSDK
      FILES_MATCHING PATTERN "*.h"
      PATTERN "CMakeFiles" EXCLUDE)

    IF(RAPIDJSON_INCLUDE_DIR)
      INSTALL(DIRECTORY ${RAPIDJSON_INCLUDE_DIR}/rapidjson
        DESTINATION ${INSTALL_SDK_INCLUDEDIR}/extra/rapidjson
        COMPONENT PluginSDK)
    ENDIF()

    IF(WITH_ZLIB STREQUAL "bundled")
      FOREACH(DIR ${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR})
        INSTALL(DIRECTORY ${DIR}/extra/zlib/${ZLIB_VERSION_DIR}/
          DESTINATION ${INSTALL_SDK_INCLUDEDIR}/extra/zlib
          COMPONENT PluginSDK
          FILES_MATCHING PATTERN "zlib.h" PATTERN "zconf.h"
          PATTERN "CMakeFiles" EXCLUDE)
      ENDFOREACH()
    ENDIF()

    INSTALL(TARGETS mysqlservices
      DESTINATION ${INSTALL_LIBDIR} COMPONENT PluginSDK)

    # Relative path from the package directory back to the install prefix.
    FILE(RELATIVE_PATH SDK_PREFIX_FROM_CMAKEDIR
      "${CMAKE_INSTALL_PREFIX}/${INSTALL_SDK_CMAKEDIR}" "${CMAKE_INSTALL_PREFIX}")
    CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/cmake/MySQLSDKConfig.cmake.in
      ${CMAKE_BINARY_DIR}/MySQLSDKConfig.cmake @ONLY)
    INSTALL(FILES ${CMAKE_BINARY_DIR}/MySQLSDKConfig.cmake
      DESTINATION ${INSTALL_SDK_CMAKEDIR}
      COMPONENT PluginSDK)
  ENDIF()
ENDMACRO()
