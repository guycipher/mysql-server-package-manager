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
  @file client/package/mysql_package_build.cc

  The package helper. mysqld runs it to resolve, fetch, verify and, when
  allowed, build a package, so the server itself never contacts a registry
  or parses what one serves. It writes key=value lines that mysqld reads.

    mysql_package_build resolve --registry URL --name NAME --constraint SPEC
        --key KEY --libc LIBC --trust-roots FILE --staging DIR
        [--allow-source --sdk-prefix DIR --timeout SECONDS]
    mysql_package_build check --registry URL --name NAME --version VERSION
        --key KEY --libc LIBC --trust-roots FILE
*/

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

#include "client/package/registry.h"
#include "client/package/source_build.h"
#include "mysql/package/signature.h"
#include "mysql/package/version.h"

using namespace package_build;
using mysql::package::Version;

namespace {

/* Values never carry a line break, so each line is one key=value. */
void emit(const std::string &key, std::string value) {
  for (char &c : value)
    if (c == '\n' || c == '\r') c = ' ';
  printf("%s=%s\n", key.c_str(), value.c_str());
}

int report(const Failure &failure) {
  emit("status", "error");
  emit("error", failure.error);
  for (const std::string &arg : failure.args) emit("arg", arg);
  return 1;
}

int usage(const std::string &why) {
  Failure failure{"ER_PACKAGE_HELPER_FAILED", {why}};
  return report(failure);
}

std::string join(const std::vector<std::string> &items) {
  std::string out;
  for (const std::string &item : items) out += (out.empty() ? "" : ", ") + item;
  return out.empty() ? "none" : out;
}

/* The server version is the first field of the compatibility key. */
bool server_version(const std::string &key, Version *version) {
  const size_t slash = key.find('/');
  return key.compare(0, 6, "mysql-") == 0 && slash != std::string::npos &&
         version->parse(key.substr(6, slash - 6));
}

bool server_supported(const Manifest &manifest, const Version &server) {
  bool valid = false;
  return mysql::package::version_satisfies(server, manifest.server_spec,
                                           &valid) &&
         valid;
}

const Binary *binary_for(const Manifest &manifest, const std::string &key) {
  for (const Binary &binary : manifest.binaries)
    if (binary.key == key) return &binary;
  return nullptr;
}

std::vector<std::string> keys_of(const Manifest &manifest) {
  std::vector<std::string> keys;
  for (const Binary &binary : manifest.binaries) keys.push_back(binary.key);
  return keys;
}

/* Native dependencies are found through pkg-config. */
bool requirements_met(const Manifest &manifest, const std::string &work_dir,
                      Failure *failure) {
  for (const auto &[library, constraint] : manifest.requirements) {
    const std::string out = work_dir + "/requires.txt";
    bool timed_out = false;
    const int status = run_program({"pkg-config", "--modversion", library}, "",
                                   {}, 30, out, &timed_out);
    std::string found;
    if (FILE *f = fopen(out.c_str(), "r")) {
      char line[128] = "";
      if (fgets(line, sizeof(line), f) != nullptr) found = line;
      fclose(f);
      std::filesystem::remove(out);
    }
    while (!found.empty() && (found.back() == '\n' || found.back() == '\r'))
      found.pop_back();
    Version version;
    bool valid = false;
    const bool met =
        status == 0 && version.parse(found) &&
        mysql::package::version_satisfies(version, constraint, &valid) && valid;
    if (!met) {
      failure->error = "ER_PACKAGE_DEPENDENCY";
      failure->args = {manifest.name, library, constraint,
                       status == 0 ? "found " + found : "not found"};
      return false;
    }
  }
  return true;
}

void emit_package(const Manifest &manifest, const std::string &origin) {
  emit("status", "ok");
  emit("name", manifest.name);
  emit("version", manifest.version);
  for (const Object &object : manifest.objects) {
    std::string description = object.type;
    for (const std::string *part :
         {&object.name, &object.plugin_type, &object.returns})
      if (!part->empty()) description += " " + *part;
    emit("object", description);
  }
  emit("origin", origin);
}

int resolve(std::map<std::string, std::string> &opt,
            const mysql::package::Trust_roots &roots) {
  Version server;
  if (!server_version(opt["key"], &server))
    return usage("--key is not a compatibility key");
  const std::string &constraint = opt["constraint"];
  {
    bool valid = false;
    mysql::package::version_satisfies(server, constraint, &valid);
    if (!valid) return usage("invalid version constraint " + constraint);
  }

  Registry registry(opt["registry"], &roots);
  Failure failure;
  std::vector<Index_entry> entries;
  if (!registry.versions(opt["name"], &entries, &failure))
    return report(failure);

  std::vector<std::string> all_versions;
  std::vector<Index_entry> candidates;
  for (const Index_entry &entry : entries) {
    all_versions.push_back(entry.version_text);
    bool valid = false;
    if (mysql::package::version_satisfies(entry.version, constraint, &valid))
      candidates.push_back(entry);
  }
  std::sort(candidates.begin(), candidates.end(),
            [](const Index_entry &a, const Index_entry &b) {
              return a.version.compare(b.version) > 0;
            });

  const bool allow_source = opt.count("allow-source") != 0;
  const std::string &key = opt["key"];
  const std::string &libc = opt["libc"];
  const std::string staging = opt["staging"];
  const Manifest *first_supported = nullptr;
  std::vector<Manifest> manifests;
  manifests.reserve(candidates.size());

  for (const Index_entry &entry : candidates) {
    manifests.emplace_back();
    Manifest &manifest = manifests.back();
    if (!registry.manifest(entry, &manifest, &failure)) return report(failure);
    if (!server_supported(manifest, server)) continue;
    if (first_supported == nullptr) first_supported = &manifest;

    const Binary *binary = binary_for(manifest, key);
    const bool binary_ok =
        binary != nullptr && mysql::package::libc_satisfies(binary->libc, libc);
    if (!binary_ok && !(allow_source && manifest.has_source)) continue;

    if (!requirements_met(manifest, staging, &failure)) return report(failure);

    if (binary_ok) {
      const std::string artifact =
          staging + "/" +
          std::filesystem::path(binary->url).filename().string();
      if (!registry.fetch_to_file(binary->url, artifact, &failure))
        return report(failure);
      std::string digest;
      if (!mysql::package::sha256_file_hex(artifact, &digest) ||
          digest != binary->sha256) {
        failure.error = "ER_PACKAGE_DIGEST_MISMATCH";
        failure.args = {manifest.name, manifest.version};
        return report(failure);
      }
      emit_package(manifest, "binary");
      emit("key", key);
      emit("sha256", digest);
      emit("signature", binary->signature);
      emit("staged", artifact);
      return 0;
    }

    const std::string artifact =
        staging + "/" +
        std::filesystem::path(manifest.source.produces).filename().string();
    const unsigned timeout =
        static_cast<unsigned>(std::max(1L, atol(opt["timeout"].c_str())));
    if (!build_from_source(manifest, opt["sdk-prefix"], staging, artifact,
                           timeout, &failure))
      return report(failure);
    std::string digest;
    if (!mysql::package::sha256_file_hex(artifact, &digest))
      return usage("cannot read the built artifact");
    emit_package(manifest, "source");
    emit("key", key);
    emit("sha256", digest);
    emit("staged", artifact);
    return 0;
  }

  if (first_supported == nullptr) {
    failure.error = "ER_PACKAGE_NO_MATCHING_VERSION";
    failure.args = {opt["name"], constraint.empty() ? "latest" : constraint,
                    join(all_versions)};
  } else if (const Binary *binary = binary_for(*first_supported, key)) {
    failure.error = "ER_PACKAGE_LIBC_TOO_NEW";
    failure.args = {first_supported->name, first_supported->version,
                    binary->libc, libc};
  } else if (first_supported->has_source) {
    failure.error = "ER_PACKAGE_SOURCE_BUILD_DISABLED";
    failure.args = {first_supported->name, first_supported->version, key};
  } else {
    failure.error = "ER_PACKAGE_NO_ARTIFACT";
    failure.args = {first_supported->name, first_supported->version, key,
                    join(keys_of(*first_supported))};
  }
  return report(failure);
}

/* Whether an installed version also has an artifact for a target key. */
int check(std::map<std::string, std::string> &opt,
          const mysql::package::Trust_roots &roots) {
  Version target;
  if (!server_version(opt["key"], &target))
    return usage("--key is not a compatibility key");
  Registry registry(opt["registry"], &roots);
  Failure failure;
  std::vector<Index_entry> entries;
  if (!registry.versions(opt["name"], &entries, &failure))
    return report(failure);
  for (const Index_entry &entry : entries) {
    if (entry.version_text != opt["version"]) continue;
    Manifest manifest;
    if (!registry.manifest(entry, &manifest, &failure)) return report(failure);
    const Binary *binary = binary_for(manifest, opt["key"]);
    emit("status", "ok");
    if (!server_supported(manifest, target)) {
      emit("available", "no");
      emit("note", "requires server " + manifest.server_spec);
    } else if (binary == nullptr) {
      emit("available", manifest.has_source ? "source" : "no");
      emit("note", "no artifact for " + opt["key"]);
    } else if (!mysql::package::libc_satisfies(binary->libc, opt["libc"])) {
      emit("available", "no");
      emit("note", "needs " + binary->libc);
    } else {
      emit("available", "yes");
      emit("note", "artifact for " + opt["key"]);
    }
    return 0;
  }
  failure.error = "ER_PACKAGE_NOT_FOUND";
  failure.args = {opt["name"] + " " + opt["version"], opt["registry"]};
  return report(failure);
}

}  // namespace

int main(int argc, char **argv) {
  if (argc < 2) return usage("usage: mysql_package_build resolve|check ...");
  const std::string command = argv[1];
  std::map<std::string, std::string> opt;
  for (int i = 2; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg.compare(0, 2, "--") != 0) return usage("unexpected " + arg);
    arg = arg.substr(2);
    if (arg == "allow-source") {
      opt[arg] = "1";
      continue;
    }
    if (i + 1 == argc) return usage("--" + arg + " needs a value");
    opt[arg] = argv[++i];
  }

  for (const char *needed : {"registry", "name", "key", "libc", "trust-roots"})
    if (opt[needed].empty())
      return usage(std::string("--") + needed + " is required");

  mysql::package::Trust_roots roots;
  std::string why;
  if (!roots.load(opt["trust-roots"], &why)) return usage(why);
  if (roots.empty()) {
    Failure failure{"ER_PACKAGES_DISABLED", {}};
    return report(failure);
  }

  if (command == "resolve") {
    if (opt["staging"].empty()) return usage("--staging is required");
    return resolve(opt, roots);
  }
  if (command == "check") {
    if (opt["version"].empty()) return usage("--version is required");
    return check(opt, roots);
  }
  return usage("unknown command " + command);
}
