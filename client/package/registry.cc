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

#include "client/package/registry.h"

#include <cctype>
#include <fstream>
#include <set>
#include <sstream>

#ifdef HAVE_PACKAGE_CURL
#include <curl/curl.h>
#endif

#include "mysql/package/toml.h"

using mysql::package::Toml_document;
using mysql::package::toml_string;
using mysql::package::Toml_table;

namespace package_build {

namespace {

constexpr size_t max_download = 512UL * 1024 * 1024;

#ifdef HAVE_PACKAGE_CURL
size_t append_body(char *data, size_t size, size_t count, void *target) {
  std::string *body = static_cast<std::string *>(target);
  if (body->size() + size * count > max_download) return 0;
  body->append(data, size * count);
  return size * count;
}
#endif

bool is_sha256(const std::string &hex) {
  if (hex.size() != 64) return false;
  for (const char c : hex)
    if (!isxdigit(static_cast<unsigned char>(c)) ||
        isupper(static_cast<unsigned char>(c)))
      return false;
  return true;
}

bool is_name(const std::string &name) {
  if (name.empty() || name.size() > 64) return false;
  for (const char c : name)
    if (!isalnum(static_cast<unsigned char>(c)) && c != '_') return false;
  return true;
}

/* An exact server version, =X.Y.Z or X.Y.Z, as version locked plugins need. */
bool is_exact_spec(const std::string &spec) {
  const std::string version =
      spec.compare(0, 1, "=") == 0 ? spec.substr(1) : spec;
  mysql::package::Version parsed;
  return version.find_first_of(" ,<>^~") == std::string::npos &&
         parsed.parse(version);
}

bool invalid(const std::string &name, const std::string &why,
             Failure *failure) {
  failure->error = "ER_PACKAGE_MANIFEST_INVALID";
  failure->args = {name, why};
  return false;
}

bool required(const Toml_table &table, const char *key, std::string *value) {
  const std::string *found = toml_string(table, key);
  if (found == nullptr || found->empty()) return false;
  *value = *found;
  return true;
}

}  // namespace

bool is_version_locked(const std::string &plugin_type) {
  return plugin_type == "storage_engine" || plugin_type == "daemon" ||
         plugin_type == "information_schema";
}

std::string Registry::resolve(const std::string &url) const {
  if (url.find("://") != std::string::npos) return url;
  std::string base = m_url;
  while (!base.empty() && base.back() == '/') base.pop_back();
  return base + "/" + url;
}

bool Registry::fetch(const std::string &url, std::string *body,
                     Failure *failure) {
  body->clear();
  if (url.compare(0, 7, "file://") == 0) {
    std::ifstream in(url.substr(7), std::ios::binary);
    if (in) {
      std::ostringstream content;
      content << in.rdbuf();
      *body = content.str();
      return true;
    }
  }
#ifdef HAVE_PACKAGE_CURL
  else if (url.compare(0, 8, "https://") == 0) {
    CURL *curl = curl_easy_init();
    if (curl != nullptr) {
      curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
      curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
      curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
      curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append_body);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, body);
      const CURLcode rc = curl_easy_perform(curl);
      curl_easy_cleanup(curl);
      if (rc == CURLE_OK) return true;
    }
  }
#endif
  failure->error = "ER_PACKAGE_HELPER_FAILED";
  failure->args = {"cannot fetch " + url};
  return false;
}

bool Registry::fetch_to_file(const std::string &url, const std::string &path,
                             Failure *failure) {
  std::string body;
  if (!fetch(resolve(url), &body, failure)) return false;
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out.write(body.data(), body.size());
  out.close();
  if (out) return true;
  failure->error = "ER_PACKAGE_HELPER_FAILED";
  failure->args = {"cannot write " + path};
  return false;
}

bool Registry::versions(const std::string &name,
                        std::vector<Index_entry> *entries, Failure *failure) {
  const std::string index_url = resolve("index.toml");
  std::string index, signature;
  if (!fetch(index_url, &index, failure) ||
      !fetch(index_url + ".sig", &signature, failure))
    return false;
  if (!m_roots->verify(index, signature)) {
    failure->error = "ER_PACKAGE_BAD_SIGNATURE";
    failure->args = {index_url};
    return false;
  }

  Toml_document doc;
  std::string why;
  if (!mysql::package::parse_toml(index, &doc, &why) ||
      doc.root.count("format") == 0 || doc.root.at("format").integer_value != 1)
    return invalid("index.toml", why.empty() ? "unknown format" : why, failure);

  entries->clear();
  std::set<std::string> seen;
  for (const Toml_table &table : doc.table_arrays["package"]) {
    Index_entry entry;
    if (!required(table, "name", &entry.name) ||
        !required(table, "version", &entry.version_text) ||
        !required(table, "manifest", &entry.manifest_path) ||
        !required(table, "sha256", &entry.manifest_sha256) ||
        !entry.version.parse(entry.version_text) ||
        !is_sha256(entry.manifest_sha256))
      return invalid("index.toml", "malformed [[package]] entry", failure);
    if (entry.name != name) continue;
    if (!seen.insert(entry.version_text).second)
      return invalid(
          "index.toml",
          "version " + entry.version_text + " of " + name + " is listed twice",
          failure);
    entries->push_back(entry);
  }
  if (entries->empty()) {
    failure->error = "ER_PACKAGE_NOT_FOUND";
    failure->args = {name, m_url};
    return false;
  }
  return true;
}

bool Registry::manifest(const Index_entry &entry, Manifest *manifest,
                        Failure *failure) {
  const std::string url = resolve(entry.manifest_path);
  std::string text, signature;
  if (!fetch(url, &text, failure) || !fetch(url + ".sig", &signature, failure))
    return false;
  if (mysql::package::sha256_hex(text) != entry.manifest_sha256 ||
      !m_roots->verify(text, signature)) {
    failure->error = "ER_PACKAGE_BAD_SIGNATURE";
    failure->args = {url};
    return false;
  }

  Toml_document doc;
  std::string why;
  if (!mysql::package::parse_toml(text, &doc, &why))
    return invalid(entry.name, why, failure);

  *manifest = Manifest();
  const Toml_table &package = doc.tables["package"];
  if (!required(package, "name", &manifest->name) ||
      !required(package, "version", &manifest->version) ||
      manifest->name != entry.name || manifest->version != entry.version_text)
    return invalid(entry.name, "[package] does not match the index", failure);

  bool locked = false;
  int components = 0;
  for (const Toml_table &table : doc.table_arrays["object"]) {
    Object object;
    if (!required(table, "type", &object.type))
      return invalid(entry.name, "an [[object]] has no type", failure);
    if (object.type == "plugin") {
      if (!required(table, "name", &object.name) || !is_name(object.name) ||
          !required(table, "plugin_type", &object.plugin_type))
        return invalid(entry.name, "a plugin needs a name and a plugin_type",
                       failure);
      locked = locked || is_version_locked(object.plugin_type);
    } else if (object.type == "function") {
      if (!required(table, "name", &object.name) || !is_name(object.name) ||
          !required(table, "returns", &object.returns) ||
          (object.returns != "STRING" && object.returns != "INTEGER" &&
           object.returns != "REAL" && object.returns != "DECIMAL"))
        return invalid(entry.name,
                       "a function needs a name and returns STRING, INTEGER, "
                       "REAL or DECIMAL",
                       failure);
    } else if (object.type == "component") {
      ++components;
    } else {
      return invalid(entry.name, "unknown object type " + object.type, failure);
    }
    manifest->objects.push_back(object);
  }
  if (manifest->objects.empty())
    return invalid(entry.name, "the package installs nothing", failure);
  if (components > 1)
    return invalid(entry.name, "a package holds at most one component",
                   failure);

  if (!required(doc.tables["compat"], "server", &manifest->server_spec))
    return invalid(entry.name, "[compat] server is missing", failure);
  if (locked && !is_exact_spec(manifest->server_spec))
    return invalid(entry.name,
                   "a storage engine, daemon or information schema plugin "
                   "needs an exact [compat] server version",
                   failure);

  for (const auto &requirement : doc.tables["requires"]) {
    if (requirement.second.type != mysql::package::Toml_value::Type::string)
      return invalid(entry.name, "[requires] values are version constraints",
                     failure);
    manifest->requirements.emplace_back(requirement.first,
                                        requirement.second.string_value);
  }

  for (const Toml_table &table : doc.table_arrays["binary"]) {
    Binary binary;
    if (!required(table, "key", &binary.key) ||
        !required(table, "url", &binary.url) ||
        !required(table, "sha256", &binary.sha256) ||
        !required(table, "signature", &binary.signature) ||
        !is_sha256(binary.sha256))
      return invalid(entry.name,
                     "a [[binary]] needs key, url, sha256 and signature",
                     failure);
    const std::string *libc = toml_string(table, "libc");
    if (libc != nullptr) binary.libc = *libc;
    manifest->binaries.push_back(binary);
  }

  if (doc.tables.count("source") != 0) {
    const Toml_table &source = doc.tables["source"];
    manifest->has_source = true;
    if (!required(source, "git", &manifest->source.git) ||
        !required(source, "tag", &manifest->source.tag) ||
        !required(source, "commit", &manifest->source.commit) ||
        !required(source, "build", &manifest->source.build) ||
        !required(source, "produces", &manifest->source.produces))
      return invalid(entry.name,
                     "[source] needs git, tag, commit, build and produces",
                     failure);
  }
  return true;
}

}  // namespace package_build
