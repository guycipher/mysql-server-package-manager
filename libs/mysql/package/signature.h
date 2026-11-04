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

#ifndef MYSQL_PACKAGE_SIGNATURE_H
#define MYSQL_PACKAGE_SIGNATURE_H

#include <string>
#include <vector>

/// @addtogroup GroupLibsMysqlPackage
/// @{

namespace mysql::package {

/// @brief Lower case hex sha256 of bytes.
std::string sha256_hex(const std::string &bytes);

/// @brief Lower case hex sha256 of a file.
/// @return false if the file cannot be read.
bool sha256_file_hex(const std::string &path, std::string *hex);

/// @brief The line a registry signs for each prebuilt artifact. The server
/// builds it from what it is installing and verifies the signature itself.
std::string artifact_attestation(const std::string &name,
                                 const std::string &version,
                                 const std::string &compat_key,
                                 const std::string &sha256);

/// @class Trust_roots
/// @brief The ed25519 public keys allowed to sign packages, one base64
/// encoded 32 byte key per line, with # comments.
class Trust_roots {
 public:
  /// @return false with error set if the file cannot be read or a line is
  /// not a key.
  bool load(const std::string &path, std::string *error);

  /// @return true if signature, base64 encoded, is a signature of message
  /// by one of the keys.
  bool verify(const std::string &message, const std::string &signature) const;

  bool empty() const { return m_keys.empty(); }

 private:
  std::vector<std::string> m_keys;
};

/// @brief Decode base64, ignoring surrounding whitespace.
/// @return false if text is not base64.
bool base64_decode(const std::string &text, std::string *bytes);

}  // namespace mysql::package

/// @}

#endif  // MYSQL_PACKAGE_SIGNATURE_H
