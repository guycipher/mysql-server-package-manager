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

#include "sql/package/sql_package.h"

#include <fcntl.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "m_string.h"
#include "my_dir.h"
#include "my_sys.h"
#include "mysql/components/my_service.h"
#include "mysql/components/services/dynamic_loader.h"
#include "mysql/components/services/log_builtins.h"
#include "mysql/components/services/persistent_dynamic_loader.h"
#include "mysql/package/signature.h"
#include "mysql/package/version.h"
#include "mysql/sdk_identity.h"
#include "mysql/strings/m_ctype.h"
#include "mysql_sdk_build.h"
#include "mysqld_error.h"
#include "scope_guard.h"
#include "sql/auth/sql_security_ctx.h"
#include "sql/auto_thd.h"
#include "sql/dd/cache/dictionary_client.h"
#include "sql/dd/types/schema.h"
#include "sql/derror.h"
#include "sql/error_handler.h"
#include "sql/field.h"
#include "sql/item.h"
#include "sql/mysqld.h"
#include "sql/package/package.h"
#include "sql/protocol.h"
#include "sql/sql_audit.h"
#include "sql/sql_backup_lock.h"
#include "sql/sql_base.h"
#include "sql/sql_class.h"
#include "sql/sql_error.h"
#include "sql/sql_plugin.h"
#include "sql/sql_udf.h"
#include "sql/table.h"
#include "sql/thd_raii.h"
#include "sql/transaction.h"

#ifndef _WIN32
extern char **environ;
#endif

/* The compatibility key this server publishes as build_compat_key. */
#define PACKAGE_SERVER_KEY                                 \
  "mysql-" MYSQL_SDK_SERVER_VERSION "/" MYSQL_SDK_PLATFORM \
  "/" MYSQL_SDK_TOOLCHAIN "/" MYSQL_SDK_BUILD_TYPE

namespace {

#ifdef _WIN32
constexpr char library_suffix[] = ".dll";
#else
constexpr char library_suffix[] = ".so";
#endif

constexpr size_t max_helper_output = 1 << 20;
/* Fetching and verifying, on top of any source build. */
constexpr ulong helper_fetch_seconds = 300;
/* Beside a version staged for restart, what it installs. */
constexpr char pending_file[] = "pending";

/* Column positions of mysql.package and mysql.package_object. */
enum {
  PACKAGE_FIELD_NAME,
  PACKAGE_FIELD_VERSION,
  PACKAGE_FIELD_REGISTRY,
  PACKAGE_FIELD_COMPAT_KEY,
  PACKAGE_FIELD_CONSTRAINT,
  PACKAGE_FIELD_SHA256,
  PACKAGE_FIELD_ORIGIN,
  PACKAGE_FIELD_INSTALLED_AT,
  PACKAGE_FIELD_PENDING_VERSION
};
enum { OBJECT_FIELD_PACKAGE, OBJECT_FIELD_TYPE, OBJECT_FIELD_NAME };

/* Library columns of mysql.plugin, mysql.func and mysql.component. */
constexpr uint plugin_field_dl = 1;
constexpr uint func_field_dl = 2;
constexpr uint component_field_urn = 2;

struct Package_object {
  std::string type;
  std::string name;
  std::string detail;
};

struct Package_row {
  std::string name;
  std::string version;
  std::string registry;
  std::string compat_key;
  std::string constraint;
  std::string sha256;
  std::string origin;
  std::string installed_at;
  std::string pending_version;
  std::vector<Package_object> objects;
};

struct Package_settings {
  std::vector<std::string> registries;
  std::string trust_roots;
  bool allow_source{false};
  ulong build_timeout{0};
};

struct Helper_output {
  std::vector<std::pair<std::string, std::string>> lines;

  std::string value(const std::string &key) const {
    for (const auto &line : lines)
      if (line.first == key) return line.second;
    return "";
  }

  std::vector<std::string> values(const std::string &key) const {
    std::vector<std::string> found;
    for (const auto &line : lines)
      if (line.first == key) found.push_back(line.second);
    return found;
  }
};

/* A version the helper resolved and the server verified. */
struct Resolved {
  Package_row row;
  std::string staged;
  std::string signature;
};

/* Runs package work with the server's own authority, since INSTALL_PACKAGE
   alone is what the statement requires. */
class Package_security_guard {
 public:
  explicit Package_security_guard(THD *thd)
      : m_thd(thd), m_saved(thd->security_context()) {
    m_context.skip_grants("mysql.package", "localhost");
    m_thd->set_security_context(&m_context);
  }
  ~Package_security_guard() { m_thd->set_security_context(m_saved); }

 private:
  THD *m_thd;
  Security_context *m_saved;
  Security_context m_context;
};

/* Keeps the first error across the cleanup that follows it. */
class Saved_error {
 public:
  explicit Saved_error(THD *thd) {
    if (thd->is_error()) {
      m_code = thd->get_stmt_da()->mysql_errno();
      m_message = thd->get_stmt_da()->message_text();
    }
    thd->clear_error();
  }
  void raise() const {
    if (m_code != 0) my_message(m_code, m_message.c_str(), MYF(0));
  }

 private:
  uint m_code{0};
  std::string m_message;
};

std::string trim(const std::string &text) {
  const size_t first = text.find_first_not_of(" \t");
  if (first == std::string::npos) return "";
  const size_t last = text.find_last_not_of(" \t");
  return text.substr(first, last - first + 1);
}

std::string without_trailing_slash(std::string url) {
  while (!url.empty() && url.back() == '/') url.pop_back();
  return url;
}

std::string field_string(Field *field) {
  if (field->is_null()) return "";
  String buffer;
  field->val_str(&buffer);
  return std::string(buffer.ptr(), buffer.length());
}

bool check_install_package_access(THD *thd) {
  if (thd->security_context()
          ->has_global_grant(STRING_WITH_LEN("INSTALL_PACKAGE"))
          .first)
    return false;
  my_error(ER_SPECIFIC_ACCESS_DENIED_ERROR, MYF(0), "INSTALL_PACKAGE");
  return true;
}

bool read_settings(Package_settings *settings) {
  mysql_mutex_lock(&LOCK_global_system_variables);
  const std::string allowlist = opt_package_registry_allowlist == nullptr
                                    ? ""
                                    : opt_package_registry_allowlist;
  settings->allow_source = opt_package_allow_compile;
  settings->build_timeout = opt_package_build_timeout;
  mysql_mutex_unlock(&LOCK_global_system_variables);
  settings->trust_roots =
      opt_package_trust_roots == nullptr ? "" : opt_package_trust_roots;

  size_t start = 0;
  while (start <= allowlist.length()) {
    size_t end = allowlist.find(',', start);
    if (end == std::string::npos) end = allowlist.length();
    const std::string entry =
        without_trailing_slash(trim(allowlist.substr(start, end - start)));
    if (!entry.empty()) settings->registries.push_back(entry);
    start = end + 1;
  }
  if (settings->registries.empty() || settings->trust_roots.empty()) {
    my_error(ER_PACKAGES_DISABLED, MYF(0));
    return true;
  }
  return false;
}

/* Splits key=value lines, as the helper writes them. */
void parse_lines(const std::string &text, Helper_output *output) {
  size_t start = 0;
  while (start < text.size()) {
    size_t end = text.find('\n', start);
    if (end == std::string::npos) end = text.size();
    const std::string line = text.substr(start, end - start);
    const size_t equals = line.find('=');
    if (equals != std::string::npos)
      output->lines.emplace_back(line.substr(0, equals),
                                 line.substr(equals + 1));
    start = end + 1;
  }
}

/* Runs the helper and collects its key=value lines. */
bool run_helper(THD *thd, const std::vector<std::string> &args, ulong timeout,
                Helper_output *output, std::string *why) {
#ifdef _WIN32
  (void)thd;
  (void)args;
  (void)timeout;
  (void)output;
  *why = "package statements are not supported on Windows";
  return true;
#else
  int fds[2];
  if (pipe(fds) != 0) {
    *why = "cannot create a pipe to the helper";
    return true;
  }
  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO);
  posix_spawn_file_actions_addclose(&actions, fds[0]);
  posix_spawn_file_actions_addclose(&actions, fds[1]);
  posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null",
                                   O_WRONLY, 0);
  std::vector<char *> argv;
  argv.push_back(opt_package_helper);
  for (const std::string &arg : args)
    argv.push_back(const_cast<char *>(arg.c_str()));
  argv.push_back(nullptr);

  pid_t pid = 0;
  const int rc = posix_spawn(&pid, opt_package_helper, &actions, nullptr,
                             argv.data(), environ);
  posix_spawn_file_actions_destroy(&actions);
  close(fds[1]);
  if (rc != 0) {
    close(fds[0]);
    *why = std::string("cannot run ") + opt_package_helper;
    return true;
  }

  std::string text;
  const time_t deadline = time(nullptr) + static_cast<time_t>(timeout);
  bool stopped = false;
  for (;;) {
    if (thd->killed || time(nullptr) >= deadline) {
      kill(pid, SIGKILL);
      stopped = true;
      break;
    }
    pollfd ready = {fds[0], POLLIN, 0};
    const int polled = poll(&ready, 1, 1000);
    if (polled < 0 && errno == EINTR) continue;
    if (polled <= 0) continue;
    char buffer[4096];
    const ssize_t got = read(fds[0], buffer, sizeof(buffer));
    if (got <= 0) break;
    text.append(buffer, static_cast<size_t>(got));
    if (text.size() > max_helper_output) {
      kill(pid, SIGKILL);
      break;
    }
  }
  close(fds[0]);
  int status = 0;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
  if (stopped) {
    *why = thd->killed ? "the statement was killed"
                       : "the helper did not finish within " +
                             std::to_string(timeout) + " s";
    return true;
  }

  parse_lines(text, output);
  if (output->value("status").empty()) {
    *why = "the helper exited without a result";
    return true;
  }
  return false;
#endif
}

/* Raises the server error the helper named, with its arguments. */
void report_helper_error(const Helper_output &output) {
  static const struct {
    const char *name;
    int code;
  } errors[] = {
      {"ER_PACKAGES_DISABLED", ER_PACKAGES_DISABLED},
      {"ER_PACKAGE_NOT_FOUND", ER_PACKAGE_NOT_FOUND},
      {"ER_PACKAGE_NO_MATCHING_VERSION", ER_PACKAGE_NO_MATCHING_VERSION},
      {"ER_PACKAGE_NO_ARTIFACT", ER_PACKAGE_NO_ARTIFACT},
      {"ER_PACKAGE_LIBC_TOO_NEW", ER_PACKAGE_LIBC_TOO_NEW},
      {"ER_PACKAGE_SOURCE_BUILD_DISABLED", ER_PACKAGE_SOURCE_BUILD_DISABLED},
      {"ER_PACKAGE_BAD_SIGNATURE", ER_PACKAGE_BAD_SIGNATURE},
      {"ER_PACKAGE_DIGEST_MISMATCH", ER_PACKAGE_DIGEST_MISMATCH},
      {"ER_PACKAGE_MANIFEST_INVALID", ER_PACKAGE_MANIFEST_INVALID},
      {"ER_PACKAGE_DEPENDENCY", ER_PACKAGE_DEPENDENCY},
      {"ER_PACKAGE_HELPER_FAILED", ER_PACKAGE_HELPER_FAILED},
  };
  std::vector<std::string> args = output.values("arg");
  args.resize(4);
  const std::string name = output.value("error");
  for (const auto &error : errors) {
    if (name != error.name) continue;
    my_error(error.code, MYF(0), args[0].c_str(), args[1].c_str(),
             args[2].c_str(), args[3].c_str());
    return;
  }
  my_error(ER_PACKAGE_HELPER_FAILED, MYF(0),
           ("unknown helper error " + name).c_str());
}

bool remove_tree(const std::string &path) {
  MY_DIR *dir = my_dir(path.c_str(), MYF(MY_WANT_STAT));
  if (dir != nullptr) {
    for (uint i = 0; i < dir->number_off_files; ++i) {
      const char *entry = dir->dir_entry[i].name;
      if (strcmp(entry, ".") == 0 || strcmp(entry, "..") == 0) continue;
      const std::string child = path + FN_LIBCHAR + entry;
      if (MY_S_ISDIR(dir->dir_entry[i].mystat->st_mode))
        remove_tree(child);
      else
        my_delete(child.c_str(), MYF(0));
    }
    my_dirend(dir);
  }
  return rmdir(path.c_str()) != 0;
}

std::string store_path(const std::string &name) {
  return std::string(opt_package_store_dir) + name;
}

std::string version_path(const std::string &name, const std::string &version) {
  return store_path(name) + FN_LIBCHAR + version;
}

bool make_directory(const std::string &path) {
  return my_mkdir(path.c_str(), 0750, MYF(0)) != 0 && errno != EEXIST;
}

/* The artifact stored for a version of a package. */
std::string stored_file(const std::string &name, const std::string &version) {
  std::string file;
  MY_DIR *dir = my_dir(version_path(name, version).c_str(), MYF(MY_WANT_STAT));
  if (dir == nullptr) return file;
  for (uint i = 0; i < dir->number_off_files && file.empty(); ++i) {
    const char *entry = dir->dir_entry[i].name;
    if (!MY_S_ISDIR(dir->dir_entry[i].mystat->st_mode) &&
        strcmp(entry, pending_file) != 0)
      file = entry;
  }
  my_dirend(dir);
  return file;
}

bool write_file(const std::string &path, const std::string &text) {
  const File file = my_create(path.c_str(), 0640, O_WRONLY | O_TRUNC, MYF(0));
  if (file < 0) return true;
  const bool failed =
      my_write(file, reinterpret_cast<const uchar *>(text.data()), text.size(),
               MYF(MY_NABP)) != 0;
  return my_close(file, MYF(0)) != 0 || failed;
}

bool read_file(const std::string &path, std::string *text) {
  const File file = my_open(path.c_str(), O_RDONLY, MYF(0));
  if (file < 0) return true;
  char buffer[4096];
  size_t got;
  while ((got = my_read(file, reinterpret_cast<uchar *>(buffer), sizeof(buffer),
                        MYF(0))) != 0 &&
         got != MY_FILE_ERROR)
    text->append(buffer, got);
  my_close(file, MYF(0));
  return got == MY_FILE_ERROR;
}

/* Creates the directory the helper stages a package into. */
bool make_staging(THD *thd, const std::string &name, std::string *staging) {
  const std::string staging_root = store_path(".staging");
  *staging =
      staging_root + FN_LIBCHAR + name + "." + std::to_string(thd->thread_id());
  remove_tree(*staging);
  if (make_directory(opt_package_store_dir) || make_directory(staging_root) ||
      make_directory(*staging)) {
    my_error(ER_PACKAGE_HELPER_FAILED, MYF(0),
             ("cannot create " + *staging).c_str());
    return true;
  }
  return false;
}

/* Reads every package, or only one when name is set. */
bool read_packages(THD *thd, const std::string &name,
                   std::vector<Package_row> *rows) {
  Table_ref tables[2] = {Table_ref("mysql", "package", TL_READ),
                         Table_ref("mysql", "package_object", TL_READ)};
  tables[0].next_local = tables[0].next_global = &tables[1];
  if (open_trans_system_tables_for_read(thd, tables)) {
    my_error(ER_PACKAGE_TABLE_INCORRECT, MYF(0));
    return true;
  }
  auto close_guard =
      create_scope_guard([thd] { close_trans_system_tables(thd); });

  TABLE *package = tables[0].table;
  package->use_all_columns();
  if (package->file->ha_rnd_init(true)) return true;
  int error;
  while (!(error = package->file->ha_rnd_next(package->record[0]))) {
    Package_row row;
    row.name = field_string(package->field[PACKAGE_FIELD_NAME]);
    if (!name.empty() && row.name != name) continue;
    row.version = field_string(package->field[PACKAGE_FIELD_VERSION]);
    row.registry = field_string(package->field[PACKAGE_FIELD_REGISTRY]);
    row.compat_key = field_string(package->field[PACKAGE_FIELD_COMPAT_KEY]);
    row.constraint = field_string(package->field[PACKAGE_FIELD_CONSTRAINT]);
    row.sha256 = field_string(package->field[PACKAGE_FIELD_SHA256]);
    row.origin = field_string(package->field[PACKAGE_FIELD_ORIGIN]);
    row.installed_at = field_string(package->field[PACKAGE_FIELD_INSTALLED_AT]);
    row.pending_version =
        field_string(package->field[PACKAGE_FIELD_PENDING_VERSION]);
    rows->push_back(row);
  }
  package->file->ha_rnd_end();
  if (error != HA_ERR_END_OF_FILE) return true;

  TABLE *objects = tables[1].table;
  objects->use_all_columns();
  if (objects->file->ha_rnd_init(true)) return true;
  while (!(error = objects->file->ha_rnd_next(objects->record[0]))) {
    const std::string owner =
        field_string(objects->field[OBJECT_FIELD_PACKAGE]);
    for (Package_row &row : *rows)
      if (row.name == owner)
        row.objects.push_back({field_string(objects->field[OBJECT_FIELD_TYPE]),
                               field_string(objects->field[OBJECT_FIELD_NAME]),
                               ""});
  }
  objects->file->ha_rnd_end();
  return error != HA_ERR_END_OF_FILE;
}

/* Deletes every row of the package, then writes row and its objects
   unless row is null. */
int replace_package_rows(THD *thd, TABLE *package, TABLE *objects,
                         const std::string &name, const Package_row *row) {
  int error = 0;
  for (TABLE *table : {package, objects}) {
    if ((error = table->file->ha_rnd_init(true))) return error;
    while (!(error = table->file->ha_rnd_next(table->record[0]))) {
      if (field_string(table->field[0]) == name &&
          (error = table->file->ha_delete_row(table->record[0])))
        break;
    }
    table->file->ha_rnd_end();
    if (error != HA_ERR_END_OF_FILE) return error;
  }
  if (row == nullptr) return 0;

  restore_record(package, s->default_values);
  const struct {
    int field;
    const std::string &value;
  } values[] = {
      {PACKAGE_FIELD_NAME, row->name},
      {PACKAGE_FIELD_VERSION, row->version},
      {PACKAGE_FIELD_REGISTRY, row->registry},
      {PACKAGE_FIELD_COMPAT_KEY, row->compat_key},
      {PACKAGE_FIELD_CONSTRAINT, row->constraint},
      {PACKAGE_FIELD_SHA256, row->sha256},
      {PACKAGE_FIELD_ORIGIN, row->origin},
  };
  for (const auto &value : values)
    package->field[value.field]->store(
        value.value.c_str(), value.value.length(), system_charset_info);
  if (row->installed_at.empty()) {
    const my_timeval now = thd->query_start_timeval_trunc(0);
    package->field[PACKAGE_FIELD_INSTALLED_AT]->store_timestamp(&now);
  } else {
    package->field[PACKAGE_FIELD_INSTALLED_AT]->store(
        row->installed_at.c_str(), row->installed_at.length(),
        system_charset_info);
  }
  if (row->pending_version.empty()) {
    package->field[PACKAGE_FIELD_PENDING_VERSION]->set_null();
  } else {
    package->field[PACKAGE_FIELD_PENDING_VERSION]->set_notnull();
    package->field[PACKAGE_FIELD_PENDING_VERSION]->store(
        row->pending_version.c_str(), row->pending_version.length(),
        system_charset_info);
  }
  if ((error = package->file->ha_write_row(package->record[0]))) return error;

  for (const Package_object &object : row->objects) {
    restore_record(objects, s->default_values);
    objects->field[OBJECT_FIELD_PACKAGE]->store(
        row->name.c_str(), row->name.length(), system_charset_info);
    objects->field[OBJECT_FIELD_TYPE]->store(
        object.type.c_str(), object.type.length(), system_charset_info);
    objects->field[OBJECT_FIELD_NAME]->store(
        object.name.c_str(), object.name.length(), system_charset_info);
    if ((error = objects->file->ha_write_row(objects->record[0]))) break;
  }
  return error;
}

/* Replaces the rows of the package with row, or removes them when row is
   null, in one transaction that is not replicated. */
bool write_package(THD *thd, const std::string &name, const Package_row *row) {
  Table_ref tables[2] = {Table_ref("mysql", "package", TL_WRITE),
                         Table_ref("mysql", "package_object", TL_WRITE)};
  tables[0].next_local = tables[0].next_global = &tables[1];
  const Disable_autocommit_guard autocommit_guard(thd);
  const Disable_binlog_guard binlog_guard(thd);
  if (open_and_lock_tables(thd, tables, MYSQL_LOCK_IGNORE_TIMEOUT)) {
    my_error(ER_PACKAGE_TABLE_INCORRECT, MYF(0));
    return end_transaction(thd, true);
  }
  tables[0].table->use_all_columns();
  tables[1].table->use_all_columns();
  const int error =
      replace_package_rows(thd, tables[0].table, tables[1].table, name, row);
  if (error) tables[0].table->file->print_error(error, MYF(0));
  return end_transaction(thd, error != 0);
}

/* Rewrites the rows whose field equals from, or starts with it when prefix
   is set, so that it holds to instead. */
int rewrite_rows(TABLE *table, uint field, const std::string &from,
                 const std::string &to, bool prefix) {
  int error = table->file->ha_rnd_init(true);
  if (error) return error;
  while (!(error = table->file->ha_rnd_next(table->record[0]))) {
    const std::string value = field_string(table->field[field]);
    if (prefix ? value.compare(0, from.length(), from) != 0 : value != from)
      continue;
    store_record(table, record[1]);
    table->field[field]->store(to.c_str(), to.length(), system_charset_info);
    if ((error =
             table->file->ha_update_row(table->record[1], table->record[0])))
      break;
  }
  table->file->ha_rnd_end();
  return error == HA_ERR_END_OF_FILE ? 0 : error;
}

/* An audit event for each install, upgrade and removal. */
void audit_package(THD *thd, const char *operation, const Package_row &row,
                   const std::string &previous) {
  const std::pair<const char *, const std::string *> values[] = {
      {"name", &row.name},     {"version", &row.version},
      {"previous", &previous}, {"compat_key", &row.compat_key},
      {"sha256", &row.sha256}, {"registry", &row.registry},
      {"origin", &row.origin},
  };
  mysql_event_tracking_message_key_value_t map[std::size(values)];
  for (size_t i = 0; i < std::size(values); ++i) {
    map[i].key = {values[i].first, strlen(values[i].first)};
    map[i].value_type = EVENT_TRACKING_MESSAGE_VALUE_TYPE_STR;
    map[i].value.str = {values[i].second->c_str(), values[i].second->length()};
  }
  mysql_event_tracking_message_notify(
      thd, AUDIT_EVENT(EVENT_TRACKING_MESSAGE_INTERNAL),
      STRING_WITH_LEN("mysql_server"), STRING_WITH_LEN("package"), operation,
      strlen(operation), map, std::size(map));
}

/* INSTALL COMPONENT and UNINSTALL COMPONENT through the persistent loader. */
bool load_component(THD *thd, const std::string &urn, bool unload) {
  my_service<SERVICE_TYPE(persistent_dynamic_loader)> loader(
      "persistent_dynamic_loader", srv_registry);
  if (loader) {
    my_error(ER_COMPONENTS_CANT_ACQUIRE_SERVICE_IMPLEMENTATION, MYF(0),
             "persistent_dynamic_loader");
    return true;
  }
  if (acquire_shared_backup_lock(thd, thd->variables.lock_wait_timeout))
    return true;
  const Disable_autocommit_guard autocommit_guard(thd);
  const dd::cache::Dictionary_client::Auto_releaser releaser(thd->dd_client());
  const char *urns[] = {urn.c_str()};
  bool error =
      unload ? loader->unload(thd, urns, 1) : loader->load(thd, urns, 1);
  error = end_transaction(thd, error);
  thd->mdl_context.release_transactional_locks();
  return error;
}

/* pkg:// components need the scheme, which is installed on first use. */
bool ensure_pkg_scheme(THD *thd) {
  my_h_service scheme = nullptr;
  if (!srv_registry->acquire("dynamic_loader_scheme_pkg", &scheme)) {
    srv_registry->release(scheme);
    return false;
  }
  return load_component(thd, "file://component_pkg_scheme", false);
}

/* Finds a component of urn whose name is also loaded from another URN. */
bool find_duplicate_component(const std::string &urn, std::string *name,
                              std::string *holder) {
  my_service<SERVICE_TYPE(dynamic_loader_query)> query("dynamic_loader_query",
                                                       srv_registry);
  my_h_component_iterator iterator;
  if (query || query->create(&iterator)) return false;
  std::vector<std::pair<std::string, std::string>> loaded;
  for (; !query->is_valid(iterator); query->next(iterator)) {
    const char *component_name;
    const char *component_urn;
    if (!query->get(iterator, &component_name, &component_urn))
      loaded.emplace_back(component_name, component_urn);
  }
  query->release(iterator);
  for (const auto &mine : loaded) {
    if (mine.second != urn) continue;
    for (const auto &other : loaded) {
      if (other.first != mine.first || other.second == urn) continue;
      *name = other.first;
      *holder = other.second;
      return true;
    }
  }
  return false;
}

std::string component_urn(const std::string &name, const std::string &version) {
  return "pkg://" + name + "@" + version;
}

Item_result function_result(const std::string &returns) {
  if (returns == "INTEGER") return INT_RESULT;
  if (returns == "REAL") return REAL_RESULT;
  if (returns == "DECIMAL") return DECIMAL_RESULT;
  return STRING_RESULT;
}

const char *function_returns(Item_result result) {
  switch (result) {
    case INT_RESULT:
      return "INTEGER";
    case REAL_RESULT:
      return "REAL";
    case DECIMAL_RESULT:
      return "DECIMAL";
    default:
      return "STRING";
  }
}

/* Fills in what each installed function returns, so that it can be
   created again. */
void describe_functions(std::vector<Package_object> *objects) {
  for (Package_object &object : *objects) {
    if (object.type != "function") continue;
    const udf_func *udf = find_udf(object.name.c_str(), object.name.length());
    if (udf != nullptr) object.detail = function_returns(udf->returns);
  }
}

/* Each object is installed as its own statement would be, so whatever it
   leaves open is closed before the next one, as at the end of a statement. */
bool end_object_step(THD *thd, bool error) {
  if (error) {
    trans_rollback_stmt(thd);
    trans_rollback(thd);
  }
  close_thread_tables(thd);
  thd->mdl_context.release_transactional_locks();
  return error;
}

bool install_object_step(THD *thd, const Package_row &row,
                         const Package_object &object,
                         const std::string &library) {
  if (object.type == "component") {
    const std::string urn = component_urn(row.name, row.version);
    if (ensure_pkg_scheme(thd) || load_component(thd, urn, false)) return true;
    std::string name;
    std::string holder;
    if (!find_duplicate_component(urn, &name, &holder)) return false;
    load_component(thd, urn, true);
    my_error(ER_COMPONENTS_LOAD_DUPLICATE_COMPONENT, MYF(0), name.c_str(),
             holder.c_str());
    return true;
  }

  if (library.length() > NAME_CHAR_LEN) {
    my_error(ER_PACKAGE_MANIFEST_INVALID, MYF(0), row.name.c_str(),
             "the package name, version and file name are too long");
    return true;
  }
  if (object.type == "plugin") {
    LEX_STRING dl = {const_cast<char *>(library.c_str()), library.length()};
    return install_plugin_for_package(
        thd, {object.name.c_str(), object.name.length()}, &dl);
  }
  udf_func udf;
  memset(&udf, 0, sizeof(udf));
  udf.name = {const_cast<char *>(object.name.c_str()), object.name.length()};
  udf.returns = function_result(object.detail);
  udf.type = UDFTYPE_FUNCTION;
  udf.dl = const_cast<char *>(library.c_str());
  return mysql_create_function(thd, &udf, false);
}

bool install_object(THD *thd, const Package_row &row,
                    const Package_object &object, const std::string &library) {
  return end_object_step(thd, install_object_step(thd, row, object, library));
}

bool uninstall_object_step(THD *thd, const Package_object &object) {
  if (object.type == "component") return load_component(thd, object.name, true);
  if (object.type == "plugin")
    return uninstall_plugin_for_package(
        thd, {object.name.c_str(), object.name.length()});
  LEX_STRING name = {const_cast<char *>(object.name.c_str()),
                     object.name.length()};
  return mysql_drop_function(thd, &name);
}

bool uninstall_object(THD *thd, const Package_object &object) {
  return end_object_step(thd, uninstall_object_step(thd, object));
}

/* Removes objects in reverse order, keeping the error that led here. */
void remove_objects(THD *thd, const std::vector<Package_object> &objects) {
  const Saved_error error(thd);
  for (auto it = objects.rbegin(); it != objects.rend(); ++it) {
    uninstall_object(thd, *it);
    thd->clear_error();
  }
  error.raise();
}

/* Installs every object of row from library, all of them or none. A
   component is then recorded by its URN. */
bool install_objects(THD *thd, Package_row *row, const std::string &library) {
  std::vector<Package_object> done;
  for (Package_object &object : row->objects) {
    if (install_object(thd, *row, object, library)) {
      remove_objects(thd, done);
      return true;
    }
    if (object.type == "component")
      object.name = component_urn(row->name, row->version);
    done.push_back(object);
  }
  return false;
}

/* Uninstalls every object of row, all of them or none. If one cannot be
   removed, those already removed are installed again from library. */
bool uninstall_objects(THD *thd, const Package_row &row,
                       const std::string &library) {
  std::vector<const Package_object *> removed;
  for (auto it = row.objects.rbegin(); it != row.objects.rend(); ++it) {
    if (!uninstall_object(thd, *it)) {
      removed.push_back(&*it);
      continue;
    }
    const Saved_error error(thd);
    for (auto back = removed.rbegin(); back != removed.rend(); ++back) {
      install_object(thd, row, **back, library);
      thd->clear_error();
    }
    error.raise();
    return true;
  }
  return false;
}

/* Names the first storage engine among objects that tables use, or with
   sessions set, that any session still holds, since such an engine cannot
   be unloaded until the server restarts. */
bool engine_in_use(THD *thd, const std::vector<Package_object> &objects,
                   bool sessions, std::string *engine) {
  engine->clear();
  const dd::cache::Dictionary_client::Auto_releaser releaser(thd->dd_client());
  std::vector<const dd::Schema *> schemas;
  bool fetched = false;
  for (const Package_object &object : objects) {
    if (object.type != "plugin") continue;
    const LEX_CSTRING name = {object.name.c_str(), object.name.length()};
    plugin_ref plugin =
        plugin_lock_by_name(thd, name, MYSQL_STORAGE_ENGINE_PLUGIN);
    if (plugin == nullptr) continue;
    plugin_unlock(thd, plugin);
    if (sessions && plugin_in_use(name, MYSQL_STORAGE_ENGINE_PLUGIN)) {
      *engine = object.name;
      return false;
    }
    if (!fetched && thd->dd_client()->fetch_global_components(&schemas))
      return true;
    fetched = true;
    for (const dd::Schema *schema : schemas) {
      std::vector<dd::String_type> names;
      if (thd->dd_client()->fetch_schema_table_names_by_engine(
              schema, object.name.c_str(), &names))
        return true;
      if (!names.empty()) {
        *engine = object.name;
        return false;
      }
    }
  }
  return false;
}

/* Whether two versions install the same objects. Components are the same
   whatever their URN, since that names the version, and functions must
   also return the same type. */
bool same_objects(const std::vector<Package_object> &left,
                  const std::vector<Package_object> &right) {
  auto describe = [](const std::vector<Package_object> &objects) {
    std::vector<std::string> keys;
    for (const Package_object &object : objects) {
      if (object.type == "component")
        keys.push_back(object.type);
      else if (object.type == "function")
        keys.push_back(object.type + " " + object.name + " " + object.detail);
      else
        keys.push_back(object.type + " " + object.name);
    }
    std::sort(keys.begin(), keys.end());
    return keys;
  };
  return describe(left) == describe(right);
}

bool parse_objects(const Helper_output &output,
                   std::vector<Package_object> *objects) {
  for (const std::string &line : output.values("object")) {
    Package_object object;
    const size_t first = line.find(' ');
    object.type = line.substr(0, first);
    if (first != std::string::npos) {
      const size_t second = line.find(' ', first + 1);
      object.name = line.substr(first + 1, second - first - 1);
      if (second != std::string::npos) object.detail = line.substr(second + 1);
    }
    if (object.type != "plugin" && object.type != "function" &&
        object.type != "component")
      return true;
    if (object.type != "component" && object.name.empty()) return true;
    objects->push_back(object);
  }
  return objects->empty();
}

/* Resolves name under constraint from the first of registries that has it,
   and verifies what the helper staged against the server's trust roots. */
bool resolve_package(THD *thd, const Package_settings &settings,
                     const std::vector<std::string> &registries,
                     const std::string &name, const std::string &constraint,
                     const std::string &staging, Resolved *resolved) {
  mysql::package::Trust_roots roots;
  std::string why;
  if (!roots.load(settings.trust_roots, &why) || roots.empty()) {
    if (why.empty()) {
      my_error(ER_PACKAGES_DISABLED, MYF(0));
    } else {
      my_error(ER_PACKAGE_HELPER_FAILED, MYF(0), why.c_str());
    }
    return true;
  }

  Helper_output output;
  std::string registry;
  for (const std::string &candidate : registries) {
    std::vector<std::string> args = {"resolve",
                                     "--registry",
                                     candidate,
                                     "--name",
                                     name,
                                     "--constraint",
                                     constraint,
                                     "--key",
                                     PACKAGE_SERVER_KEY,
                                     "--libc",
                                     MYSQL_SDK_LIBC,
                                     "--trust-roots",
                                     settings.trust_roots,
                                     "--staging",
                                     staging};
    if (settings.allow_source) {
      args.insert(args.end(), {"--allow-source", "--sdk-prefix",
                               std::string(mysql_home_ptr), "--timeout",
                               std::to_string(settings.build_timeout)});
    }
    output = Helper_output();
    if (run_helper(thd, args, settings.build_timeout + helper_fetch_seconds,
                   &output, &why)) {
      my_error(ER_PACKAGE_HELPER_FAILED, MYF(0), why.c_str());
      return true;
    }
    registry = candidate;
    if (output.value("status") == "ok" ||
        output.value("error") != "ER_PACKAGE_NOT_FOUND")
      break;
  }
  if (output.value("status") != "ok") {
    /* A failed build is explained in full in the error log. */
    if (output.value("error") == "ER_PACKAGE_HELPER_FAILED")
      LogErr(WARNING_LEVEL, ER_PACKAGE_LOG_HELPER_OUTPUT, name.c_str(),
             output.value("arg").c_str());
    report_helper_error(output);
    return true;
  }

  Package_row &row = resolved->row;
  row.name = output.value("name");
  row.version = output.value("version");
  row.registry = registry;
  row.compat_key = output.value("key");
  row.constraint = constraint;
  row.origin = output.value("origin");
  resolved->staged = output.value("staged");
  resolved->signature = output.value("signature");
  const std::string &staged = resolved->staged;
  if (row.name != name || !package_version_valid(row.version) ||
      row.compat_key != PACKAGE_SERVER_KEY ||
      (row.origin != "binary" && row.origin != "source") ||
      staged.compare(0, staging.length() + 1, staging + FN_LIBCHAR) != 0 ||
      staged.find("..") != std::string::npos ||
      parse_objects(output, &row.objects)) {
    my_error(ER_PACKAGE_HELPER_FAILED, MYF(0),
             "the helper reported a result for a different package");
    return true;
  }

  /* The server's own check, against its own trust roots. */
  if (!mysql::package::sha256_file_hex(staged, &row.sha256) ||
      row.sha256 != output.value("sha256")) {
    my_error(ER_PACKAGE_DIGEST_MISMATCH, MYF(0), name.c_str(),
             row.version.c_str());
    return true;
  }
  if (row.origin == "binary" &&
      !roots.verify(mysql::package::artifact_attestation(
                        row.name, row.version, row.compat_key, row.sha256),
                    resolved->signature)) {
    my_error(ER_PACKAGE_BAD_SIGNATURE, MYF(0),
             ("the artifact of " + name + " " + row.version).c_str());
    return true;
  }
  return false;
}

/* Moves the staged artifact into the store as name/version/file. A
   component is stored under the package name, which pkg:// expects. */
bool store_artifact(const Resolved &resolved, std::string *file) {
  const Package_row &row = resolved.row;
  bool has_component = false;
  for (const Package_object &object : row.objects)
    has_component = has_component || object.type == "component";
  const char *base = strrchr(resolved.staged.c_str(), FN_LIBCHAR);
  *file = has_component ? row.name + library_suffix : std::string(base + 1);
  const std::string version_dir = version_path(row.name, row.version);
  const std::string artifact = version_dir + FN_LIBCHAR + *file;
  if (make_directory(store_path(row.name)) || make_directory(version_dir) ||
      my_rename(resolved.staged.c_str(), artifact.c_str(), MYF(0))) {
    my_error(ER_PACKAGE_HELPER_FAILED, MYF(0),
             ("cannot store " + artifact).c_str());
    return true;
  }
  return false;
}

/* What a version staged for restart installs, so that startup can verify it
   again and switch to it. */
std::string pending_text(const Resolved &resolved, const std::string &file) {
  const Package_row &row = resolved.row;
  std::string text = "version=" + row.version + "\nkey=" + row.compat_key +
                     "\norigin=" + row.origin + "\nsha256=" + row.sha256 +
                     "\nsignature=" + resolved.signature +
                     "\nconstraint=" + row.constraint + "\nfile=" + file + "\n";
  for (const Package_object &object : row.objects) {
    const std::string name = object.type == "component"
                                 ? component_urn(row.name, row.version)
                                 : object.name;
    text += "object=" + object.type + " " + name +
            (object.detail.empty() ? "" : " " + object.detail) + "\n";
  }
  return text;
}

/* Switches a package to the version staged for restart. Every row that
   loads it from the previous version is rewritten in one transaction. */
bool apply_pending(THD *thd, const Package_row &row, std::string *why) {
  const std::string version_dir = version_path(row.name, row.pending_version);
  std::string text;
  Helper_output staged;
  if (read_file(version_dir + FN_LIBCHAR + pending_file, &text)) {
    *why = "its description cannot be read";
    return true;
  }
  parse_lines(text, &staged);

  Package_row next = row;
  next.version = staged.value("version");
  next.compat_key = staged.value("key");
  next.constraint = staged.value("constraint");
  next.sha256 = staged.value("sha256");
  next.origin = staged.value("origin");
  next.installed_at.clear();
  next.pending_version.clear();
  next.objects.clear();
  const std::string file = staged.value("file");
  std::string digest;
  std::string error;
  mysql::package::Trust_roots roots;
  if (next.version != row.pending_version || file.empty() ||
      file.find(FN_LIBCHAR) != std::string::npos ||
      (next.origin != "binary" && next.origin != "source") ||
      parse_objects(staged, &next.objects)) {
    *why = "its description is invalid";
  } else if (next.compat_key != PACKAGE_SERVER_KEY) {
    *why = "it was built for " + next.compat_key;
  } else if (!mysql::package::sha256_file_hex(version_dir + FN_LIBCHAR + file,
                                              &digest) ||
             digest != next.sha256) {
    *why = "the artifact does not match its sha256 digest";
  } else if (next.origin == "binary" &&
             (opt_package_trust_roots == nullptr ||
              !roots.load(opt_package_trust_roots, &error) ||
              !roots.verify(
                  mysql::package::artifact_attestation(
                      next.name, next.version, next.compat_key, next.sha256),
                  staged.value("signature")))) {
    *why =
        "the artifact signature was not made by a key in "
        "package_trust_roots";
  }
  if (!why->empty()) {
    Package_row kept = row;
    kept.pending_version.clear();
    if (!write_package(thd, row.name, &kept)) remove_tree(version_dir);
    return true;
  }

  const std::string from = "pkg://" + row.name + "@" + row.version + "/";
  const std::string to = package_library_name(next.name, next.version, file);
  Table_ref tables[5] = {Table_ref("mysql", "package", TL_WRITE),
                         Table_ref("mysql", "package_object", TL_WRITE),
                         Table_ref("mysql", "plugin", TL_WRITE),
                         Table_ref("mysql", "func", TL_WRITE),
                         Table_ref("mysql", "component", TL_WRITE)};
  for (size_t i = 0; i + 1 < std::size(tables); ++i)
    tables[i].next_local = tables[i].next_global = &tables[i + 1];
  const Disable_autocommit_guard autocommit_guard(thd);
  const Disable_binlog_guard binlog_guard(thd);
  if (open_and_lock_tables(thd, tables, MYSQL_LOCK_IGNORE_TIMEOUT)) {
    *why = "the system tables cannot be opened";
    end_transaction(thd, true);
    return true;
  }
  for (Table_ref &table : tables) table.table->use_all_columns();
  int failure = replace_package_rows(thd, tables[0].table, tables[1].table,
                                     row.name, &next);
  if (!failure)
    failure = rewrite_rows(tables[2].table, plugin_field_dl, from, to, true);
  if (!failure)
    failure = rewrite_rows(tables[3].table, func_field_dl, from, to, true);
  if (!failure)
    failure = rewrite_rows(tables[4].table, component_field_urn,
                           component_urn(row.name, row.version),
                           component_urn(next.name, next.version), false);
  if (failure) {
    *why =
        "the system tables cannot be updated, error " + std::to_string(failure);
    end_transaction(thd, true);
    return true;
  }
  if (end_transaction(thd, false)) {
    *why = "the system tables cannot be committed";
    return true;
  }
  my_delete((version_dir + FN_LIBCHAR + pending_file).c_str(), MYF(0));
  remove_tree(version_path(row.name, row.version));
  LogErr(INFORMATION_LEVEL, ER_PACKAGE_LOG_OPERATION, next.name.c_str(),
         next.version.c_str(), "upgraded at restart", next.registry.c_str(),
         next.compat_key.c_str(), next.sha256.c_str());
  return false;
}

/* A target server is named X.Y.Z, as in a compatibility key. */
bool server_version_valid(const std::string &version) {
  int dots = 0;
  bool digit = false;
  for (const char c : version) {
    if (c == '.') {
      if (!digit) return false;
      ++dots;
      digit = false;
    } else if (my_isdigit(&my_charset_latin1, c)) {
      digit = true;
    } else {
      return false;
    }
  }
  return dots == 2 && digit;
}

/* Keeps the message of an error instead of raising it. */
class Error_text_handler : public Internal_error_handler {
 public:
  bool handle_condition(THD *, uint, const char *,
                        Sql_condition::enum_severity_level *,
                        const char *message) override {
    m_text = message;
    return true;
  }
  std::string m_text;
};

/* The message of the server error the helper named. */
std::string helper_error_text(THD *thd, const Helper_output &output) {
  Error_text_handler handler;
  thd->push_internal_handler(&handler);
  report_helper_error(output);
  thd->pop_internal_handler();
  return handler.m_text;
}

bool send_rows(THD *thd, const std::vector<const char *> &columns,
               const std::vector<std::vector<std::string>> &rows) {
  mem_root_deque<Item *> fields(thd->mem_root);
  for (const char *column : columns)
    fields.push_back(new Item_empty_string(column, NAME_CHAR_LEN));
  if (thd->send_result_metadata(fields,
                                Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF))
    return true;
  Protocol *protocol = thd->get_protocol();
  for (const std::vector<std::string> &row : rows) {
    protocol->start_row();
    for (const std::string &value : row)
      protocol->store_string(value.c_str(), value.length(),
                             system_charset_info);
    if (protocol->end_row()) return true;
  }
  my_eof(thd);
  return false;
}

}  // namespace

bool Sql_cmd_install_package::execute(THD *thd) {
  Package_settings settings;
  if (read_settings(&settings) || check_install_package_access(thd))
    return true;

  const std::string name = to_string(m_name);
  const std::string constraint =
      m_constraint.str == nullptr ? "latest" : to_string(m_constraint);
  if (!package_name_valid(name)) {
    my_error(ER_WRONG_ARGUMENTS, MYF(0), "INSTALL PACKAGE");
    return true;
  }

  std::vector<std::string> registries = settings.registries;
  if (m_registry.str != nullptr) {
    const std::string wanted = without_trailing_slash(to_string(m_registry));
    bool allowed = false;
    for (const std::string &registry : settings.registries)
      allowed = allowed || registry == wanted;
    if (!allowed) {
      my_error(ER_PACKAGE_REGISTRY_NOT_ALLOWED, MYF(0), wanted.c_str());
      return true;
    }
    registries = {wanted};
  }

  std::vector<Package_row> installed;
  if (read_packages(thd, name, &installed)) return true;
  if (!installed.empty()) {
    my_error(ER_PACKAGE_ALREADY_INSTALLED, MYF(0), name.c_str(),
             installed[0].version.c_str());
    return true;
  }

  std::string staging;
  if (make_staging(thd, name, &staging)) return true;
  auto staging_guard = create_scope_guard([&] { remove_tree(staging); });

  Resolved resolved;
  std::string file;
  if (resolve_package(thd, settings, registries, name, constraint, staging,
                      &resolved) ||
      store_artifact(resolved, &file))
    return true;
  Package_row &row = resolved.row;
  const std::string library = package_library_name(name, row.version, file);

  bool failed;
  {
    const Package_security_guard security_guard(thd);
    const Disable_binlog_guard binlog_guard(thd);
    failed = install_objects(thd, &row, library);
    if (!failed && write_package(thd, name, &row)) {
      remove_objects(thd, row.objects);
      failed = true;
    }
  }
  if (failed) {
    remove_tree(version_path(name, row.version));
    rmdir(store_path(name).c_str());
    return true;
  }

  audit_package(thd, "installed", row, "");
  LogErr(INFORMATION_LEVEL, ER_PACKAGE_LOG_OPERATION, name.c_str(),
         row.version.c_str(), "installed", row.registry.c_str(),
         row.compat_key.c_str(), row.sha256.c_str());
  my_ok(thd);
  return false;
}

bool Sql_cmd_upgrade_package::execute(THD *thd) {
  Package_settings settings;
  if (read_settings(&settings) || check_install_package_access(thd))
    return true;

  const std::string name = to_string(m_name);
  std::vector<Package_row> installed;
  if (read_packages(thd, name, &installed)) return true;
  if (installed.empty()) {
    my_error(ER_PACKAGE_NOT_INSTALLED, MYF(0), name.c_str());
    return true;
  }
  Package_row previous = installed[0];
  if (!previous.pending_version.empty()) {
    my_error(ER_PACKAGE_RESTART_PENDING, MYF(0), name.c_str(),
             previous.pending_version.c_str());
    return true;
  }
  /* A package is only ever upgraded from the registry it came from. */
  bool allowed = false;
  for (const std::string &registry : settings.registries)
    allowed = allowed || registry == previous.registry;
  if (!allowed) {
    my_error(ER_PACKAGE_REGISTRY_NOT_ALLOWED, MYF(0),
             previous.registry.c_str());
    return true;
  }
  const std::string constraint = m_constraint.str == nullptr
                                     ? previous.constraint
                                     : to_string(m_constraint);

  std::string staging;
  if (make_staging(thd, name, &staging)) return true;
  auto staging_guard = create_scope_guard([&] { remove_tree(staging); });

  Resolved resolved;
  if (resolve_package(thd, settings, {previous.registry}, name, constraint,
                      staging, &resolved))
    return true;
  Package_row &row = resolved.row;

  /* Without VERSION a package never moves back. */
  mysql::package::Version from;
  mysql::package::Version to;
  from.parse(previous.version);
  to.parse(row.version);
  const int order = to.compare(from);
  if (order == 0 || (order < 0 && m_constraint.str == nullptr)) {
    if (constraint != previous.constraint) {
      Package_row kept = previous;
      kept.constraint = constraint;
      const Package_security_guard security_guard(thd);
      if (write_package(thd, name, &kept)) return true;
    }
    push_warning_printf(thd, Sql_condition::SL_NOTE, ER_PACKAGE_ALREADY_CURRENT,
                        ER_THD(thd, ER_PACKAGE_ALREADY_CURRENT), name.c_str(),
                        previous.version.c_str(), constraint.c_str());
    my_ok(thd);
    return false;
  }

  std::string file;
  if (store_artifact(resolved, &file)) return true;
  const std::string version_dir = version_path(name, row.version);
  auto store_guard = create_scope_guard([&] { remove_tree(version_dir); });

  describe_functions(&previous.objects);
  std::string engine;
  if (engine_in_use(thd, previous.objects, true, &engine)) return true;

  if (!engine.empty()) {
    /* The engine stays loaded until restart, so only its library can
       change, not what the package installs. */
    if (!same_objects(previous.objects, row.objects)) {
      my_error(ER_PACKAGE_ENGINE_IN_USE, MYF(0), name.c_str(), engine.c_str());
      return true;
    }
    if (write_file(version_dir + FN_LIBCHAR + pending_file,
                   pending_text(resolved, file))) {
      my_error(
          ER_PACKAGE_HELPER_FAILED, MYF(0),
          ("cannot write " + version_dir + FN_LIBCHAR + pending_file).c_str());
      return true;
    }
    Package_row staged = previous;
    staged.pending_version = row.version;
    {
      const Package_security_guard security_guard(thd);
      if (write_package(thd, name, &staged)) return true;
    }
    store_guard.release();
    push_warning_printf(thd, Sql_condition::SL_NOTE, ER_PACKAGE_UPGRADE_PENDING,
                        ER_THD(thd, ER_PACKAGE_UPGRADE_PENDING), name.c_str(),
                        row.version.c_str(), previous.version.c_str(),
                        engine.c_str());
    audit_package(thd, "staged", row, previous.version);
    LogErr(INFORMATION_LEVEL, ER_PACKAGE_LOG_OPERATION, name.c_str(),
           row.version.c_str(), "staged for restart", row.registry.c_str(),
           row.compat_key.c_str(), row.sha256.c_str());
    my_ok(thd);
    return false;
  }

  const std::string previous_library = package_library_name(
      name, previous.version, stored_file(name, previous.version));
  const std::string library = package_library_name(name, row.version, file);
  bool failed;
  {
    const Package_security_guard security_guard(thd);
    const Disable_binlog_guard binlog_guard(thd);
    failed = uninstall_objects(thd, previous, previous_library);
    if (!failed) {
      failed = install_objects(thd, &row, library);
      if (!failed && write_package(thd, name, &row)) {
        remove_objects(thd, row.objects);
        failed = true;
      }
      /* The previous version is still in the store, so it comes back. */
      if (failed) {
        const Saved_error error(thd);
        for (const Package_object &object : previous.objects) {
          install_object(thd, previous, object, previous_library);
          thd->clear_error();
        }
        error.raise();
      }
    }
  }
  if (failed) return true;
  store_guard.release();
  remove_tree(version_path(name, previous.version));

  audit_package(thd, "upgraded", row, previous.version);
  LogErr(INFORMATION_LEVEL, ER_PACKAGE_LOG_OPERATION, name.c_str(),
         row.version.c_str(), "upgraded", row.registry.c_str(),
         row.compat_key.c_str(), row.sha256.c_str());
  my_ok(thd);
  return false;
}

bool Sql_cmd_uninstall_package::execute(THD *thd) {
  if (check_install_package_access(thd)) return true;
  const std::string name = to_string(m_name);
  std::vector<Package_row> installed;
  if (read_packages(thd, name, &installed)) return true;
  if (installed.empty()) {
    my_error(ER_PACKAGE_NOT_INSTALLED, MYF(0), name.c_str());
    return true;
  }
  Package_row &row = installed[0];

  /* An engine only a session still holds is removed at shutdown, as
     UNINSTALL PLUGIN does. */
  std::string engine;
  if (engine_in_use(thd, row.objects, false, &engine)) return true;
  if (!engine.empty()) {
    my_error(ER_PACKAGE_ENGINE_IN_USE, MYF(0), name.c_str(), engine.c_str());
    return true;
  }

  describe_functions(&row.objects);
  const std::string library =
      package_library_name(name, row.version, stored_file(name, row.version));
  {
    const Package_security_guard security_guard(thd);
    const Disable_binlog_guard binlog_guard(thd);
    if (uninstall_objects(thd, row, library)) return true;
    if (write_package(thd, name, nullptr)) {
      const Saved_error error(thd);
      for (const Package_object &object : row.objects) {
        install_object(thd, row, object, library);
        thd->clear_error();
      }
      error.raise();
      return true;
    }
  }
  remove_tree(store_path(name));
  audit_package(thd, "uninstalled", row, "");
  LogErr(INFORMATION_LEVEL, ER_PACKAGE_LOG_OPERATION, name.c_str(),
         row.version.c_str(), "uninstalled", row.registry.c_str(),
         row.compat_key.c_str(), row.sha256.c_str());
  my_ok(thd);
  return false;
}

bool Sql_cmd_show_packages::execute(THD *thd) {
  std::vector<Package_row> packages;
  {
    const Package_security_guard security_guard(thd);
    if (read_packages(thd, "", &packages)) return true;
  }
  std::vector<std::vector<std::string>> rows;
  for (const Package_row &package : packages) {
    std::string objects;
    for (const Package_object &object : package.objects)
      objects +=
          (objects.empty() ? "" : ", ") + object.type + " " + object.name;
    rows.push_back({package.name, package.version, package.constraint,
                    package.origin, objects, package.compat_key,
                    package.registry});
  }
  return send_rows(thd,
                   {"Package", "Version", "Constraint", "Origin", "Objects",
                    "Compat_key", "Registry"},
                   rows);
}

bool Sql_cmd_show_package_status::execute(THD *thd) {
  Package_settings settings;
  if (read_settings(&settings) || check_install_package_access(thd))
    return true;

  const bool for_server = m_server.str != nullptr;
  const std::string target = for_server ? to_string(m_server) : "";
  if (for_server && !server_version_valid(target)) {
    my_error(ER_WRONG_ARGUMENTS, MYF(0), "SHOW PACKAGE STATUS FOR SERVER");
    return true;
  }
  const std::string key = for_server ? "mysql-" + target +
                                           "/" MYSQL_SDK_PLATFORM
                                           "/" MYSQL_SDK_TOOLCHAIN
                                           "/" MYSQL_SDK_BUILD_TYPE
                                     : PACKAGE_SERVER_KEY;

  const std::string name = m_name.str == nullptr ? "" : to_string(m_name);
  std::vector<Package_row> packages;
  {
    const Package_security_guard security_guard(thd);
    if (read_packages(thd, name, &packages)) return true;
  }
  if (!name.empty() && packages.empty()) {
    my_error(ER_PACKAGE_NOT_INSTALLED, MYF(0), name.c_str());
    return true;
  }

  std::vector<std::vector<std::string>> rows;
  for (const Package_row &package : packages) {
    Helper_output output;
    std::string note;
    bool allowed = false;
    for (const std::string &registry : settings.registries)
      allowed = allowed || registry == package.registry;
    if (!allowed) {
      note = "registry " + package.registry +
             " is not in package_registry_allowlist";
    } else {
      std::vector<std::string> args = {"check",
                                       "--registry",
                                       package.registry,
                                       "--name",
                                       package.name,
                                       "--version",
                                       package.version,
                                       "--constraint",
                                       package.constraint,
                                       "--key",
                                       key,
                                       "--libc",
                                       MYSQL_SDK_LIBC,
                                       "--trust-roots",
                                       settings.trust_roots};
      if (settings.allow_source) args.push_back("--allow-source");
      std::string why;
      if (run_helper(thd, args, helper_fetch_seconds, &output, &why)) {
        if (thd->killed) {
          my_error(ER_PACKAGE_HELPER_FAILED, MYF(0), why.c_str());
          return true;
        }
        note = why;
      } else if (output.value("status") != "ok") {
        note = helper_error_text(thd, output);
      } else if (for_server || output.value("available") != "yes") {
        note = output.value("note");
      }
    }

    std::string available = output.value("available");
    for (char &c : available) c = my_toupper(&my_charset_latin1, c);
    const std::string newest = output.value("newest");
    if (for_server) {
      rows.push_back({package.name, package.version, available, newest, note});
      continue;
    }
    mysql::package::Version installed;
    mysql::package::Version candidate;
    /* A version already staged for restart is not offered again. */
    const bool update =
        installed.parse(package.version) && candidate.parse(newest) &&
        candidate.compare(installed) > 0 && newest != package.pending_version;
    rows.push_back(
        {package.name, package.version, package.constraint, newest,
         output.value("status") == "ok" ? (update ? "YES" : "NO") : "",
         package.pending_version, note});
  }
  if (for_server)
    return send_rows(
        thd,
        {"Package", "Version", "Target_available", "Target_newest", "Note"},
        rows);
  return send_rows(thd,
                   {"Package", "Version", "Constraint", "Newest",
                    "Update_available", "Pending_version", "Note"},
                   rows);
}

void package_apply_pending() {
  if (opt_package_store_dir[0] == '\0') return;
  const Auto_THD auto_thd;
  THD *thd = auto_thd.thd;
  thd->set_time();
  const dd::cache::Dictionary_client::Auto_releaser releaser(thd->dd_client());

  /* A server without the package tables, as during an upgrade from an
     older release, has nothing staged. */
  std::vector<Package_row> rows;
  Dummy_error_handler quiet;
  thd->push_internal_handler(&quiet);
  const bool unreadable = read_packages(thd, "", &rows);
  thd->pop_internal_handler();
  if (unreadable) return;

  for (const Package_row &row : rows) {
    if (row.pending_version.empty()) continue;
    std::string why;
    if (apply_pending(thd, row, &why))
      LogErr(WARNING_LEVEL, ER_PACKAGE_LOG_PENDING_FAILED, row.name.c_str(),
             row.pending_version.c_str(), why.c_str());
    thd->clear_error();
  }
}
