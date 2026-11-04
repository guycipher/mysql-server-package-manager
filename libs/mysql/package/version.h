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

#ifndef MYSQL_PACKAGE_VERSION_H
#define MYSQL_PACKAGE_VERSION_H

#include <string>

/// @addtogroup GroupLibsMysqlPackage
/// @{

namespace mysql::package {

/// @brief A major.minor.patch version, with an optional -prerelease that
/// sorts before the release.
struct Version {
  unsigned major{0};
  unsigned minor{0};
  unsigned patch{0};
  std::string prerelease;

  /// @brief Parse X, X.Y or X.Y.Z with an optional -prerelease. Missing
  /// parts are zero.
  /// @return false if text is not a version.
  bool parse(const std::string &text);

  int compare(const Version &other) const;
};

/// @brief Whether version satisfies constraint. A constraint is "latest" or
/// empty for any release, or comma separated terms that must all hold, each
/// an exact X.Y.Z or =X.Y.Z, or >=, >, <=, <, ^ (same major, or same minor
/// below 1.0) and ~ (same major.minor). A prerelease only satisfies an exact
/// term naming it.
/// @param[out] valid Set to false if constraint cannot be parsed.
bool version_satisfies(const Version &version, const std::string &constraint,
                       bool *valid);

/// @brief Whether a C library floor such as glibc-2.34 is met by the
/// library the server was built against, such as glibc-2.37. Different
/// library families never satisfy each other.
bool libc_satisfies(const std::string &floor, const std::string &server_libc);

}  // namespace mysql::package

/// @}

#endif  // MYSQL_PACKAGE_VERSION_H
