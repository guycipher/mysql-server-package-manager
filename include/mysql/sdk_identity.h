/* Copyright (c) 2026, Oracle and/or its affiliates.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License, version 2.0,
   as published by the Free Software Foundation.

   This program is designed to work with certain software (including
   but not limited to OpenSSL) that is licensed under separate terms,
   as designated in a particular file or component or in included license
   documentation.  The authors of MySQL hereby grant you an additional
   permission to link the program and your derivative works with the
   separately licensed software that they have either included with
   the program or referenced in the documentation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License, version 2.0, for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#ifndef MYSQL_SDK_IDENTITY_INCLUDED
#define MYSQL_SDK_IDENTITY_INCLUDED

/**
  @file include/mysql/sdk_identity.h

  The parts of the compatibility key that come from the compiler.
  The server and an extension compute them from the same definitions.
*/

#include <limits.h>
#ifdef __cplusplus
#include <cstddef>
#endif

#define MYSQL_SDK_STR_(x) #x
#define MYSQL_SDK_STR(x) MYSQL_SDK_STR_(x)

#if defined(__clang__) && defined(__apple_build_version__)
#define MYSQL_SDK_COMPILER "appleclang" MYSQL_SDK_STR(__clang_major__)
#elif defined(__clang__)
#define MYSQL_SDK_COMPILER "clang" MYSQL_SDK_STR(__clang_major__)
#elif defined(__GNUC__)
#define MYSQL_SDK_COMPILER "gcc" MYSQL_SDK_STR(__GNUC__)
#elif defined(_MSC_VER)
#define MYSQL_SDK_COMPILER "msvc" MYSQL_SDK_STR(_MSC_VER)
#else
#define MYSQL_SDK_COMPILER "unknown"
#endif

#if defined(_LIBCPP_VERSION)
#define MYSQL_SDK_CXX_RUNTIME "-libc++"
#elif defined(_GLIBCXX_USE_CXX11_ABI) && _GLIBCXX_USE_CXX11_ABI
#define MYSQL_SDK_CXX_RUNTIME "-cxx11abi"
#elif defined(_GLIBCXX_USE_CXX11_ABI)
#define MYSQL_SDK_CXX_RUNTIME "-cxx03abi"
#else
#define MYSQL_SDK_CXX_RUNTIME ""
#endif

/** Compiler and C++ runtime ABI, e.g. gcc13-cxx11abi. */
#define MYSQL_SDK_TOOLCHAIN MYSQL_SDK_COMPILER MYSQL_SDK_CXX_RUNTIME

/** The oldest C library an artifact built here can load against. */
#if defined(__GLIBC__)
#define MYSQL_SDK_LIBC \
  "glibc-" MYSQL_SDK_STR(__GLIBC__) "." MYSQL_SDK_STR(__GLIBC_MINOR__)
#elif defined(__APPLE__)
#define MYSQL_SDK_LIBC "darwin"
#elif defined(_WIN32)
#define MYSQL_SDK_LIBC "ucrt"
#else
#define MYSQL_SDK_LIBC "unknown"
#endif

#ifdef NDEBUG
#define MYSQL_SDK_BUILD_TYPE "release"
#else
#define MYSQL_SDK_BUILD_TYPE "debug"
#endif

#endif /* MYSQL_SDK_IDENTITY_INCLUDED */
