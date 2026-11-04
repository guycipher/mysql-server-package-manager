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

#include <cctype>
#include <cstring>
#include <string>

namespace {

constexpr char package_library_prefix[] = "pkg://";
constexpr size_t package_library_prefix_length =
    sizeof(package_library_prefix) - 1;

bool package_file_valid(const std::string &file) {
  if (file.empty() || file[0] == '.' || file.find("..") != std::string::npos)
    return false;
  for (const char c : file)
    if (!isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '.' &&
        c != '-')
      return false;
  return true;
}

}  // namespace

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

bool package_name_valid(const std::string &name) {
  if (name.empty() || name.length() > 64) return false;
  for (const char c : name)
    if (!isalnum(static_cast<unsigned char>(c)) && c != '_') return false;
  return true;
}

bool package_version_valid(const std::string &version) {
  if (version.empty() || version.length() > 32 ||
      !isdigit(static_cast<unsigned char>(version[0])) ||
      version.find("..") != std::string::npos)
    return false;
  for (const char c : version)
    if (!isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-' &&
        c != '+')
      return false;
  return true;
}

bool is_package_library(const char *dl, size_t length) {
  return length > package_library_prefix_length &&
         strncmp(dl, package_library_prefix, package_library_prefix_length) ==
             0;
}

bool package_library_path(const char *dl, size_t length, char *path,
                          size_t path_size) {
  if (!is_package_library(dl, length)) return false;
  const std::string spec(dl + package_library_prefix_length,
                         length - package_library_prefix_length);
  const size_t at = spec.find('@');
  const size_t slash = spec.find('/');
  if (at == std::string::npos || slash == std::string::npos || slash < at)
    return false;
  const std::string name = spec.substr(0, at);
  const std::string version = spec.substr(at + 1, slash - at - 1);
  const std::string file = spec.substr(slash + 1);
  if (!package_name_valid(name) || !package_version_valid(version) ||
      !package_file_valid(file))
    return false;

  const std::string full = std::string(opt_package_store_dir) + name +
                           FN_LIBCHAR + version + FN_LIBCHAR + file;
  if (full.length() >= path_size) return false;
  memcpy(path, full.c_str(), full.length() + 1);
  return true;
}

std::string package_library_name(const std::string &name,
                                 const std::string &version,
                                 const std::string &file) {
  return package_library_prefix + name + "@" + version + "/" + file;
}
