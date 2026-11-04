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

#include "mysql/package/toml.h"

#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <set>

namespace mysql::package {

namespace {

bool is_key_char(char c) {
  return isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-';
}

void skip_space(const std::string &s, size_t *pos) {
  while (*pos < s.size() && (s[*pos] == ' ' || s[*pos] == '\t')) ++*pos;
}

bool at_line_end(const std::string &s, size_t pos) {
  skip_space(s, &pos);
  return pos == s.size() || s[pos] == '#';
}

bool parse_string(const std::string &s, size_t *pos, std::string *out,
                  std::string *why) {
  ++*pos;
  out->clear();
  while (*pos < s.size()) {
    const char c = s[(*pos)++];
    if (c == '"') return true;
    if (c == '\\') {
      if (*pos == s.size()) break;
      switch (s[(*pos)++]) {
        case '"':
          out->push_back('"');
          break;
        case '\\':
          out->push_back('\\');
          break;
        case 'n':
          out->push_back('\n');
          break;
        case 't':
          out->push_back('\t');
          break;
        default:
          *why = "unsupported escape in string";
          return false;
      }
      continue;
    }
    if (static_cast<unsigned char>(c) < 0x20 && c != '\t') {
      *why = "control character in string";
      return false;
    }
    out->push_back(c);
  }
  *why = "unterminated string";
  return false;
}

bool starts_word(const std::string &s, size_t pos, const char *word) {
  const std::string w(word);
  return s.compare(pos, w.size(), w) == 0 &&
         (pos + w.size() == s.size() || !is_key_char(s[pos + w.size()]));
}

bool parse_value(const std::string &s, size_t *pos, Toml_value *value,
                 std::string *why) {
  if (*pos == s.size()) {
    *why = "missing value";
    return false;
  }
  if (s[*pos] == '"') {
    value->type = Toml_value::Type::string;
    return parse_string(s, pos, &value->string_value, why);
  }
  if (s[*pos] == '[') {
    value->type = Toml_value::Type::string_array;
    ++*pos;
    skip_space(s, pos);
    if (*pos < s.size() && s[*pos] == ']') {
      ++*pos;
      return true;
    }
    while (*pos < s.size()) {
      skip_space(s, pos);
      if (*pos == s.size() || s[*pos] != '"') break;
      std::string item;
      if (!parse_string(s, pos, &item, why)) return false;
      value->array_value.push_back(item);
      skip_space(s, pos);
      if (*pos < s.size() && s[*pos] == ',') {
        ++*pos;
        continue;
      }
      if (*pos < s.size() && s[*pos] == ']') {
        ++*pos;
        return true;
      }
      break;
    }
    *why = "arrays hold strings and close on the same line";
    return false;
  }
  if (starts_word(s, *pos, "true") || starts_word(s, *pos, "false")) {
    value->type = Toml_value::Type::boolean;
    value->boolean_value = s[*pos] == 't';
    *pos += value->boolean_value ? 4 : 5;
    return true;
  }
  const size_t start = *pos;
  if (s[*pos] == '+' || s[*pos] == '-') ++*pos;
  while (*pos < s.size() && isdigit(static_cast<unsigned char>(s[*pos])))
    ++*pos;
  if (*pos == start || !isdigit(static_cast<unsigned char>(s[*pos - 1]))) {
    *why = "unsupported value";
    return false;
  }
  errno = 0;
  value->type = Toml_value::Type::integer;
  value->integer_value = strtoll(s.c_str() + start, nullptr, 10);
  if (errno == ERANGE) {
    *why = "integer out of range";
    return false;
  }
  return true;
}

bool parse_table_name(const std::string &s, size_t open, size_t close,
                      std::string *name) {
  size_t start = open;
  skip_space(s, &start);
  size_t end = start;
  while (end < close && (is_key_char(s[end]) || s[end] == '.')) ++end;
  *name = s.substr(start, end - start);
  skip_space(s, &end);
  return !name->empty() && end == close;
}

}  // namespace

bool parse_toml(const std::string &text, Toml_document *doc,
                std::string *error) {
  *doc = Toml_document();
  Toml_table *current = &doc->root;
  std::set<std::string> tables_seen;
  size_t line_start = 0;
  int line_number = 0;

  while (line_start <= text.size()) {
    size_t line_end = text.find('\n', line_start);
    if (line_end == std::string::npos) line_end = text.size();
    std::string line = text.substr(line_start, line_end - line_start);
    line_start = line_end + 1;
    ++line_number;
    if (!line.empty() && line.back() == '\r') line.pop_back();

    std::string why;
    size_t pos = 0;
    skip_space(line, &pos);
    if (at_line_end(line, pos)) continue;

    if (line.compare(pos, 2, "[[") == 0) {
      const size_t close = line.find("]]", pos);
      std::string name;
      if (close == std::string::npos ||
          !parse_table_name(line, pos + 2, close, &name) ||
          !at_line_end(line, close + 2))
        why = "malformed [[table]] header";
      else if (doc->tables.count(name) != 0)
        why = "[[" + name + "]] is already a table";
      else {
        std::vector<Toml_table> &array = doc->table_arrays[name];
        array.emplace_back();
        current = &array.back();
      }
    } else if (line[pos] == '[') {
      const size_t close = line.find(']', pos);
      std::string name;
      if (close == std::string::npos ||
          !parse_table_name(line, pos + 1, close, &name) ||
          !at_line_end(line, close + 1))
        why = "malformed [table] header";
      else if (!tables_seen.insert(name).second ||
               doc->table_arrays.count(name) != 0)
        why = "table [" + name + "] is defined twice";
      else
        current = &doc->tables[name];
    } else {
      const size_t key_start = pos;
      while (pos < line.size() && is_key_char(line[pos])) ++pos;
      const std::string key = line.substr(key_start, pos - key_start);
      skip_space(line, &pos);
      Toml_value value;
      if (key.empty() || pos == line.size() || line[pos] != '=')
        why = "expected key = value";
      else {
        ++pos;
        skip_space(line, &pos);
        if (parse_value(line, &pos, &value, &why) && !at_line_end(line, pos))
          why = "unexpected text after value";
      }
      if (why.empty() && !current->emplace(key, value).second)
        why = "key '" + key + "' is defined twice";
    }

    if (!why.empty()) {
      *error = "line " + std::to_string(line_number) + ": " + why;
      return false;
    }
  }
  return true;
}

const std::string *toml_string(const Toml_table &table,
                               const std::string &key) {
  const auto it = table.find(key);
  if (it == table.end() || it->second.type != Toml_value::Type::string)
    return nullptr;
  return &it->second.string_value;
}

}  // namespace mysql::package
