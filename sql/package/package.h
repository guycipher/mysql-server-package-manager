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

#ifndef SQL_PACKAGE_PACKAGE_H
#define SQL_PACKAGE_PACKAGE_H

/**
  @file sql/package/package.h

  Server options for installing extensions as packages.
*/

#include <cstddef>
#include <string>

#include "my_inttypes.h"
#include "my_io.h"

extern char *opt_package_store_dir_ptr;
extern char opt_package_store_dir[FN_REFLEN];
extern char *opt_package_helper_ptr;
extern char opt_package_helper[FN_REFLEN];
extern char *opt_package_trust_roots;
extern char *opt_package_registry_allowlist;
extern bool opt_package_allow_compile;
extern ulong opt_package_build_timeout;

/** Every package_registry_allowlist entry names an https:// or file:// URL. */
bool package_registry_allowlist_valid(const char *list);

/** Letters, digits and _, at most 64 characters. */
bool package_name_valid(const std::string &name);

/** Starts with a digit, and holds no path separator or "..". */
bool package_version_valid(const std::string &version);

/**
  Whether a plugin or function library name is a package artifact,
  pkg://name@version/file, rather than a file in plugin_dir.
*/
bool is_package_library(const char *dl, size_t length);

/**
  The file a package artifact name refers to, under package_store_dir.

  @return false if the name is malformed or the path does not fit.
*/
bool package_library_path(const char *dl, size_t length, char *path,
                          size_t path_size);

/** The library name of a package artifact, pkg://name@version/file. */
std::string package_library_name(const std::string &name,
                                 const std::string &version,
                                 const std::string &file);

#endif /* SQL_PACKAGE_PACKAGE_H */
