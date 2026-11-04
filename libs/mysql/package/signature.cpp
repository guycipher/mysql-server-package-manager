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

#include "mysql/package/signature.h"

#include <openssl/evp.h>

#include <fstream>
#include <memory>
#include <sstream>

namespace mysql::package {

namespace {

constexpr size_t ed25519_key_length = 32;
constexpr size_t ed25519_signature_length = 64;

std::string to_hex(const unsigned char *bytes, size_t length) {
  static const char digits[] = "0123456789abcdef";
  std::string hex;
  hex.reserve(length * 2);
  for (size_t i = 0; i < length; ++i) {
    hex.push_back(digits[bytes[i] >> 4]);
    hex.push_back(digits[bytes[i] & 0xf]);
  }
  return hex;
}

std::string trim(const std::string &text) {
  const size_t first = text.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return "";
  const size_t last = text.find_last_not_of(" \t\r\n");
  return text.substr(first, last - first + 1);
}

}  // namespace

std::string sha256_hex(const std::string &bytes) {
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int length = 0;
  EVP_Digest(bytes.data(), bytes.size(), digest, &length, EVP_sha256(),
             nullptr);
  return to_hex(digest, length);
}

bool sha256_file_hex(const std::string &path, std::string *hex) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return false;
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),
                                                              EVP_MD_CTX_free);
  if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1)
    return false;
  char buffer[1 << 16];
  while (in) {
    in.read(buffer, sizeof(buffer));
    if (in.gcount() > 0 &&
        EVP_DigestUpdate(ctx.get(), buffer, in.gcount()) != 1)
      return false;
  }
  if (in.bad()) return false;
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int length = 0;
  if (EVP_DigestFinal_ex(ctx.get(), digest, &length) != 1) return false;
  *hex = to_hex(digest, length);
  return true;
}

std::string artifact_attestation(const std::string &name,
                                 const std::string &version,
                                 const std::string &compat_key,
                                 const std::string &sha256) {
  return "mysql-package-artifact 1 " + name + " " + version + " " + compat_key +
         " " + sha256;
}

bool base64_decode(const std::string &text, std::string *bytes) {
  const std::string in = trim(text);
  if (in.empty() || in.size() % 4 != 0) return false;
  std::string out(in.size() / 4 * 3, '\0');
  const int length =
      EVP_DecodeBlock(reinterpret_cast<unsigned char *>(out.data()),
                      reinterpret_cast<const unsigned char *>(in.data()),
                      static_cast<int>(in.size()));
  if (length < 0) return false;
  size_t padding = 0;
  if (in[in.size() - 1] == '=') ++padding;
  if (in[in.size() - 2] == '=') ++padding;
  out.resize(length - padding);
  *bytes = out;
  return true;
}

bool Trust_roots::load(const std::string &path, std::string *error) {
  m_keys.clear();
  std::ifstream in(path);
  if (!in) {
    *error = "cannot read " + path;
    return false;
  }
  std::string line;
  int line_number = 0;
  while (std::getline(in, line)) {
    ++line_number;
    line = trim(line);
    if (line.empty() || line[0] == '#') continue;
    std::string key;
    if (!base64_decode(line, &key) || key.size() != ed25519_key_length) {
      *error = path + " line " + std::to_string(line_number) +
               " is not a base64 ed25519 public key";
      return false;
    }
    m_keys.push_back(key);
  }
  return true;
}

bool Trust_roots::verify(const std::string &message,
                         const std::string &signature) const {
  std::string raw;
  if (!base64_decode(signature, &raw) || raw.size() != ed25519_signature_length)
    return false;
  for (const std::string &key : m_keys) {
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
        EVP_PKEY_new_raw_public_key(
            EVP_PKEY_ED25519, nullptr,
            reinterpret_cast<const unsigned char *>(key.data()), key.size()),
        EVP_PKEY_free);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(
        EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!pkey || !ctx ||
        EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr,
                             pkey.get()) != 1)
      continue;
    if (EVP_DigestVerify(
            ctx.get(), reinterpret_cast<const unsigned char *>(raw.data()),
            raw.size(), reinterpret_cast<const unsigned char *>(message.data()),
            message.size()) == 1)
      return true;
  }
  return false;
}

}  // namespace mysql::package
