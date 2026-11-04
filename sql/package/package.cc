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

#include "sql/package/package.h"

#include <string>

char *opt_package_store_dir_ptr;
char opt_package_store_dir[FN_REFLEN];
char *opt_package_helper_ptr;
char opt_package_helper[FN_REFLEN];
char *opt_package_trust_roots;
char *opt_package_registry_allowlist;
bool opt_package_allow_source_build;
ulong opt_package_build_timeout;

bool package_registry_allowlist_valid(const char *list) {
  if (list == nullptr) return true;
  const std::string entries(list);
  size_t start = 0;
  while (start <= entries.length()) {
    size_t end = entries.find(',', start);
    if (end == std::string::npos) end = entries.length();
    std::string entry = entries.substr(start, end - start);
    const size_t first = entry.find_first_not_of(' ');
    const size_t last = entry.find_last_not_of(' ');
    entry =
        first == std::string::npos ? "" : entry.substr(first, last - first + 1);
    if (!entry.empty() && entry.compare(0, 8, "https://") != 0 &&
        entry.compare(0, 7, "file://") != 0)
      return false;
    start = end + 1;
  }
  return true;
}
