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

#ifndef CLIENT_PACKAGE_REGISTRY_H
#define CLIENT_PACKAGE_REGISTRY_H

/**
  @file client/package/registry.h

  Reading a package registry: the signed index, signed manifests and
  artifacts, over https:// or from a file:// directory.
*/

#include <string>
#include <vector>

#include "mysql/package/signature.h"
#include "mysql/package/version.h"

namespace package_build {

/** A failure reported to the server by error name and arguments. */
struct Failure {
  std::string error;
  std::vector<std::string> args;
};

struct Index_entry {
  std::string name;
  std::string version_text;
  mysql::package::Version version;
  std::string manifest_path;
  std::string manifest_sha256;
};

struct Object {
  std::string type;
  std::string name;
  std::string plugin_type;
  std::string returns;
};

struct Binary {
  std::string key;
  std::string libc;
  std::string url;
  std::string sha256;
  std::string signature;
};

struct Source {
  std::string git;
  std::string tag;
  std::string commit;
  std::string build;
  std::string produces;
};

struct Manifest {
  std::string name;
  std::string version;
  std::vector<Object> objects;
  std::string server_spec;
  std::vector<std::pair<std::string, std::string>> requirements;
  std::vector<Binary> binaries;
  bool has_source{false};
  Source source;
};

class Registry {
 public:
  Registry(std::string url, const mysql::package::Trust_roots *roots)
      : m_url(std::move(url)), m_roots(roots) {}

  /** Fetch and verify index.toml, and list the versions of name. */
  bool versions(const std::string &name, std::vector<Index_entry> *entries,
                Failure *failure);

  /** Fetch a manifest, check it against its index digest and signature. */
  bool manifest(const Index_entry &entry, Manifest *manifest, Failure *failure);

  /** Fetch an artifact, by a URL that may be relative to the registry. */
  bool fetch_to_file(const std::string &url, const std::string &path,
                     Failure *failure);

  const std::string &url() const { return m_url; }

 private:
  bool fetch(const std::string &url, std::string *body, Failure *failure);
  std::string resolve(const std::string &url) const;

  std::string m_url;
  const mysql::package::Trust_roots *m_roots;
};

/** Plugin types that are bound to one exact server version. */
bool is_version_locked(const std::string &plugin_type);

}  // namespace package_build

#endif  // CLIENT_PACKAGE_REGISTRY_H
