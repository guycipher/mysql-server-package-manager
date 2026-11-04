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

/**
  @file components/pkg_scheme/pkg_scheme.cc

  The pkg:// dynamic loader scheme. pkg://name@version names an artifact the
  package manager has verified and staged as name/version/name under
  package_store_dir. Loading is passed on to the minimal chassis file://
  scheme, which keeps its duplicate library guard.
*/

#include <mysql/components/component_implementation.h>
#include <mysql/components/service_implementation.h>
#include <mysql/components/services/dynamic_loader.h>
#include <mysql/components/services/dynamic_loader_scheme_file.h>
#include <mysql/components/services/mysql_system_variable.h>

#include <cctype>
#include <cstring>
#include <mutex>
#include <set>
#include <string>

typedef SERVICE_TYPE_NO_CONST(dynamic_loader_scheme)
    SERVICE_TYPE_NO_CONST(dynamic_loader_scheme_pkg);

REQUIRES_SERVICE_PLACEHOLDER(dynamic_loader_scheme_file);
REQUIRES_SERVICE_PLACEHOLDER(mysql_system_variable_reader);

namespace {

constexpr size_t max_name_length = 64;
constexpr size_t max_version_length = 32;
/* The server's FN_REFLEN. */
constexpr size_t max_path_length = 512;

std::string store_dir;
std::mutex loaded_lock;
std::set<std::string> loaded_urns;

bool valid_name(const std::string &name) {
  if (name.empty() || name.length() > max_name_length) return false;
  for (const char c : name)
    if (!isalnum(static_cast<unsigned char>(c)) && c != '_') return false;
  return true;
}

bool valid_version(const std::string &version) {
  if (version.empty() || version.length() > max_version_length) return false;
  if (!isdigit(static_cast<unsigned char>(version[0]))) return false;
  if (version.find("..") != std::string::npos) return false;
  for (const char c : version)
    if (!isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-' &&
        c != '+')
      return false;
  return true;
}

/* pkg://name@version becomes file://<store>/name/version/name. */
bool make_file_urn(const char *urn, std::string *file_urn) {
  if (urn == nullptr) return true;
  const char *spec = strstr(urn, "://");
  if (spec == nullptr) return true;
  spec += 3;
  const char *at = strchr(spec, '@');
  if (at == nullptr) return true;

  const std::string name(spec, at);
  const std::string version(at + 1);
  if (!valid_name(name) || !valid_version(version)) return true;

  *file_urn = "file://" + store_dir + name + '/' + version + '/' + name;
  return false;
}

}  // namespace

static DEFINE_BOOL_METHOD(pkg_load,
                          (const char *urn, mysql_component_t **out_data)) {
  try {
    std::string file_urn;
    if (make_file_urn(urn, &file_urn)) return true;

    const std::lock_guard<std::mutex> guard(loaded_lock);
    if (mysql_service_dynamic_loader_scheme_file->load(file_urn.c_str(),
                                                       out_data))
      return true;
    loaded_urns.insert(urn);
    return false;
  } catch (...) {
  }
  return true;
}

static DEFINE_BOOL_METHOD(pkg_unload, (const char *urn)) {
  try {
    std::string file_urn;
    if (make_file_urn(urn, &file_urn)) return true;

    const std::lock_guard<std::mutex> guard(loaded_lock);
    if (mysql_service_dynamic_loader_scheme_file->unload(file_urn.c_str()))
      return true;
    loaded_urns.erase(urn);
    return false;
  } catch (...) {
  }
  return true;
}

static mysql_service_status_t pkg_scheme_init() {
  char buffer[max_path_length + 1];
  char *value = buffer;
  size_t length = sizeof(buffer) - 1;
  if (mysql_service_mysql_system_variable_reader->get(
          nullptr, "GLOBAL", "mysql_server", "package_store_dir",
          reinterpret_cast<void **>(&value), &length))
    return true;

  store_dir.assign(value, length);
  if (store_dir.empty() ||
      (store_dir.back() != '/' && store_dir.back() != '\\'))
    store_dir += '/';
  return false;
}

/* Components loaded through this scheme are unloaded through it too. */
static mysql_service_status_t pkg_scheme_deinit() {
  const std::lock_guard<std::mutex> guard(loaded_lock);
  return !loaded_urns.empty();
}

BEGIN_SERVICE_IMPLEMENTATION(pkg_scheme, dynamic_loader_scheme_pkg)
pkg_load, pkg_unload END_SERVICE_IMPLEMENTATION();

BEGIN_COMPONENT_PROVIDES(pkg_scheme)
PROVIDES_SERVICE(pkg_scheme, dynamic_loader_scheme_pkg),
    END_COMPONENT_PROVIDES();

BEGIN_COMPONENT_REQUIRES(pkg_scheme)
REQUIRES_SERVICE_IMPLEMENTATION(dynamic_loader_scheme_file,
                                mysql_minimal_chassis),
    REQUIRES_SERVICE(mysql_system_variable_reader), END_COMPONENT_REQUIRES();

BEGIN_COMPONENT_METADATA(pkg_scheme)
METADATA("mysql.author", "Oracle Corporation"),
    METADATA("mysql.license", "GPL"), END_COMPONENT_METADATA();

DECLARE_COMPONENT(pkg_scheme, "mysql:pkg_scheme")
pkg_scheme_init, pkg_scheme_deinit END_DECLARE_COMPONENT();

DECLARE_LIBRARY_COMPONENTS &COMPONENT_REF(pkg_scheme)
    END_DECLARE_LIBRARY_COMPONENTS
