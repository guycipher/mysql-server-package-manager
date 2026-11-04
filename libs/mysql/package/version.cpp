// Copyright (c) 2026, Oracle and/or its affiliates.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License, version 2.0,
// as published by the Free Software Foundation.
//
// This program is designed to work with certain software (including
// but not limited to OpenSSL) that is licensed under separate terms,
// as designated in a particular file or component or in included license
// documentation.  The authors of MySQL hereby grant you an additional
// permission to link the program and your derivative works with the
// separately licensed software that they have either included with
// the program or referenced in the documentation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License, version 2.0, for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA

#include "mysql/package/version.h"

#include <cctype>

namespace mysql::package {

namespace {

bool parse_number(const std::string &text, size_t *pos, unsigned *value) {
  const size_t start = *pos;
  unsigned long result = 0;
  while (*pos < text.size() &&
         isdigit(static_cast<unsigned char>(text[*pos]))) {
    result = result * 10 + (text[*pos] - '0');
    if (result > 999999) return false;
    ++*pos;
  }
  *value = static_cast<unsigned>(result);
  return *pos > start;
}

std::string trim(const std::string &text) {
  const size_t first = text.find_first_not_of(" \t");
  if (first == std::string::npos) return "";
  const size_t last = text.find_last_not_of(" \t");
  return text.substr(first, last - first + 1);
}

bool term_satisfied(const Version &version, std::string term, bool *valid) {
  term = trim(term);
  std::string op;
  for (const char *candidate : {">=", "<=", ">", "<", "=", "^", "~"}) {
    const std::string c(candidate);
    if (term.compare(0, c.size(), c) == 0) {
      op = c;
      break;
    }
  }
  Version bound;
  if (!bound.parse(trim(term.substr(op.size())))) {
    *valid = false;
    return false;
  }
  const int order = version.compare(bound);
  if (op.empty() || op == "=") return order == 0;
  if (!version.prerelease.empty()) return false;
  if (op == ">=") return order >= 0;
  if (op == ">") return order > 0;
  if (op == "<=") return order <= 0;
  if (op == "<") return order < 0;
  if (order < 0) return false;
  if (op == "~")
    return version.major == bound.major && version.minor == bound.minor;
  if (bound.major > 0) return version.major == bound.major;
  return version.major == 0 && version.minor == bound.minor;
}

}  // namespace

bool Version::parse(const std::string &text) {
  *this = Version();
  size_t pos = 0;
  if (!parse_number(text, &pos, &major)) return false;
  if (pos < text.size() && text[pos] == '.') {
    ++pos;
    if (!parse_number(text, &pos, &minor)) return false;
    if (pos < text.size() && text[pos] == '.') {
      ++pos;
      if (!parse_number(text, &pos, &patch)) return false;
    }
  }
  if (pos < text.size() && text[pos] == '-') {
    prerelease = text.substr(pos + 1);
    if (prerelease.empty()) return false;
    for (const char c : prerelease)
      if (!isalnum(static_cast<unsigned char>(c)) && c != '.') return false;
    pos = text.size();
  }
  return pos == text.size();
}

int Version::compare(const Version &other) const {
  if (major != other.major) return major < other.major ? -1 : 1;
  if (minor != other.minor) return minor < other.minor ? -1 : 1;
  if (patch != other.patch) return patch < other.patch ? -1 : 1;
  if (prerelease == other.prerelease) return 0;
  if (prerelease.empty()) return 1;
  if (other.prerelease.empty()) return -1;
  return prerelease < other.prerelease ? -1 : 1;
}

bool version_satisfies(const Version &version, const std::string &constraint,
                       bool *valid) {
  *valid = true;
  const std::string spec = trim(constraint);
  if (spec.empty() || spec == "latest") return version.prerelease.empty();
  bool satisfied = true;
  size_t start = 0;
  while (start <= spec.size()) {
    size_t end = spec.find(',', start);
    if (end == std::string::npos) end = spec.size();
    if (!term_satisfied(version, spec.substr(start, end - start), valid))
      satisfied = false;
    if (!*valid) return false;
    start = end + 1;
  }
  return satisfied;
}

bool libc_satisfies(const std::string &floor, const std::string &server_libc) {
  if (floor.empty()) return true;
  const size_t floor_dash = floor.rfind('-');
  const size_t server_dash = server_libc.rfind('-');
  if (floor_dash == std::string::npos || server_dash == std::string::npos)
    return floor == server_libc;
  if (floor.compare(0, floor_dash, server_libc, 0, server_dash) != 0)
    return false;
  Version needed, available;
  if (!needed.parse(floor.substr(floor_dash + 1)) ||
      !available.parse(server_libc.substr(server_dash + 1)))
    return floor == server_libc;
  return available.compare(needed) >= 0;
}

}  // namespace mysql::package
