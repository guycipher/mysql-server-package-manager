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

#ifndef MYSQL_PACKAGE_TOML_H
#define MYSQL_PACKAGE_TOML_H

#include <map>
#include <string>
#include <vector>

/// @addtogroup GroupLibsMysqlPackage
/// @{

namespace mysql::package {

/// @brief A TOML value of the kinds package manifests and indexes use.
struct Toml_value {
  enum class Type { string, integer, boolean, string_array };
  Type type{Type::string};
  std::string string_value;
  long long integer_value{0};
  bool boolean_value{false};
  std::vector<std::string> array_value;
};

using Toml_table = std::map<std::string, Toml_value>;

/// @brief A parsed TOML document. Keys outside any table are in root,
/// [name] tables in tables and [[name]] arrays of tables in table_arrays.
struct Toml_document {
  Toml_table root;
  std::map<std::string, Toml_table> tables;
  std::map<std::string, std::vector<Toml_table>> table_arrays;
};

/// @brief Parse the TOML subset package files use: comments, [table],
/// [[array]], and keys holding basic strings, integers, booleans or
/// one-line arrays of strings. Duplicate keys and tables are errors.
/// @param text The document.
/// @param[out] doc The parsed document.
/// @param[out] error On failure, the line number and what was wrong.
/// @return true on success.
bool parse_toml(const std::string &text, Toml_document *doc,
                std::string *error);

/// @brief The string value of key in table, or nullptr if absent or not a
/// string.
const std::string *toml_string(const Toml_table &table, const std::string &key);

}  // namespace mysql::package

/// @}

#endif  // MYSQL_PACKAGE_TOML_H
