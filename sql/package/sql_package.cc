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

#include <cerrno>
#include <cstring>
#include <ctime>
#include <string>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
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
#include "mysql/components/services/log_builtins.h"
#include "mysql/components/services/persistent_dynamic_loader.h"
#include "mysql/package/signature.h"
#include "mysql/sdk_identity.h"
#include "mysql_sdk_build.h"
#include "mysqld_error.h"
#include "scope_guard.h"
#include "sql/auth/sql_security_ctx.h"
#include "sql/dd/cache/dictionary_client.h"
#include "sql/field.h"
#include "sql/item.h"
#include "sql/mysqld.h"
#include "sql/package/package.h"
#include "sql/protocol.h"
#include "sql/sql_backup_lock.h"
#include "sql/sql_base.h"
#include "sql/sql_class.h"
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
  settings->allow_source = opt_package_allow_source_build;
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

bool make_directory(const std::string &path) {
  return my_mkdir(path.c_str(), 0750, MYF(0)) != 0 && errno != EEXIST;
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

/* Writes row and its objects, or with remove set deletes every row for
   the package. Neither is replicated. */
bool write_package(THD *thd, const Package_row &row, bool remove) {
  Table_ref tables[2] = {Table_ref("mysql", "package", TL_WRITE),
                         Table_ref("mysql", "package_object", TL_WRITE)};
  tables[0].next_local = tables[0].next_global = &tables[1];
  const Disable_autocommit_guard autocommit_guard(thd);
  const Disable_binlog_guard binlog_guard(thd);
  if (open_and_lock_tables(thd, tables, MYSQL_LOCK_IGNORE_TIMEOUT)) {
    my_error(ER_PACKAGE_TABLE_INCORRECT, MYF(0));
    return end_transaction(thd, true);
  }
  TABLE *package = tables[0].table;
  TABLE *objects = tables[1].table;
  package->use_all_columns();
  objects->use_all_columns();
  int error = 0;

  if (remove) {
    for (TABLE *table : {package, objects}) {
      if ((error = table->file->ha_rnd_init(true))) break;
      while (!(error = table->file->ha_rnd_next(table->record[0]))) {
        if (field_string(table->field[0]) == row.name &&
            (error = table->file->ha_delete_row(table->record[0])))
          break;
      }
      table->file->ha_rnd_end();
      if (error != HA_ERR_END_OF_FILE) break;
      error = 0;
    }
    return end_transaction(thd, error != 0);
  }

  restore_record(package, s->default_values);
  const struct {
    int field;
    const std::string &value;
  } values[] = {
      {PACKAGE_FIELD_NAME, row.name},
      {PACKAGE_FIELD_VERSION, row.version},
      {PACKAGE_FIELD_REGISTRY, row.registry},
      {PACKAGE_FIELD_COMPAT_KEY, row.compat_key},
      {PACKAGE_FIELD_CONSTRAINT, row.constraint},
      {PACKAGE_FIELD_SHA256, row.sha256},
      {PACKAGE_FIELD_ORIGIN, row.origin},
  };
  for (const auto &value : values)
    package->field[value.field]->store(
        value.value.c_str(), value.value.length(), system_charset_info);
  const my_timeval now = thd->query_start_timeval_trunc(0);
  package->field[PACKAGE_FIELD_INSTALLED_AT]->store_timestamp(&now);
  package->field[PACKAGE_FIELD_PENDING_VERSION]->set_null();
  error = package->file->ha_write_row(package->record[0]);

  for (const Package_object &object : row.objects) {
    if (error) break;
    restore_record(objects, s->default_values);
    objects->field[OBJECT_FIELD_PACKAGE]->store(
        row.name.c_str(), row.name.length(), system_charset_info);
    objects->field[OBJECT_FIELD_TYPE]->store(
        object.type.c_str(), object.type.length(), system_charset_info);
    objects->field[OBJECT_FIELD_NAME]->store(
        object.name.c_str(), object.name.length(), system_charset_info);
    error = objects->file->ha_write_row(objects->record[0]);
  }
  if (error) package->file->print_error(error, MYF(0));
  return end_transaction(thd, error != 0);
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

std::string component_urn(const std::string &name, const std::string &version) {
  return "pkg://" + name + "@" + version;
}

Item_result function_result(const std::string &returns) {
  if (returns == "INTEGER") return INT_RESULT;
  if (returns == "REAL") return REAL_RESULT;
  if (returns == "DECIMAL") return DECIMAL_RESULT;
  return STRING_RESULT;
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
  if (object.type == "component")
    return ensure_pkg_scheme(thd) ||
           load_component(thd, component_urn(row.name, row.version), false);

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

  const std::string staging_root = store_path(".staging");
  const std::string staging =
      staging_root + FN_LIBCHAR + name + "." + std::to_string(thd->thread_id());
  remove_tree(staging);
  if (make_directory(opt_package_store_dir) || make_directory(staging_root) ||
      make_directory(staging)) {
    my_error(ER_PACKAGE_HELPER_FAILED, MYF(0),
             ("cannot create " + staging).c_str());
    return true;
  }
  auto staging_guard = create_scope_guard([&] { remove_tree(staging); });

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
    report_helper_error(output);
    return true;
  }

  Package_row row;
  row.name = output.value("name");
  row.version = output.value("version");
  row.registry = registry;
  row.compat_key = output.value("key");
  row.constraint = constraint;
  row.origin = output.value("origin");
  const std::string staged = output.value("staged");
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
                    output.value("signature"))) {
    my_error(ER_PACKAGE_BAD_SIGNATURE, MYF(0),
             ("the artifact of " + name + " " + row.version).c_str());
    return true;
  }

  bool has_component = false;
  for (const Package_object &object : row.objects)
    has_component = has_component || object.type == "component";
  const char *base = strrchr(staged.c_str(), FN_LIBCHAR);
  const std::string file =
      has_component ? name + library_suffix : std::string(base + 1);
  const std::string package_dir = store_path(name);
  const std::string version_dir = package_dir + FN_LIBCHAR + row.version;
  const std::string artifact = version_dir + FN_LIBCHAR + file;
  if (make_directory(package_dir) || make_directory(version_dir) ||
      my_rename(staged.c_str(), artifact.c_str(), MYF(0))) {
    my_error(ER_PACKAGE_HELPER_FAILED, MYF(0),
             ("cannot store " + artifact).c_str());
    return true;
  }
  const std::string library = package_library_name(name, row.version, file);

  std::vector<Package_object> done;
  bool failed = false;
  {
    const Package_security_guard security_guard(thd);
    const Disable_binlog_guard binlog_guard(thd);
    for (Package_object &object : row.objects) {
      if (install_object(thd, row, object, library)) {
        failed = true;
        break;
      }
      if (object.type == "component")
        object.name = component_urn(row.name, row.version);
      done.push_back(object);
    }
    failed = failed || write_package(thd, row, false);
    if (failed) {
      const Saved_error error(thd);
      for (auto it = done.rbegin(); it != done.rend(); ++it) {
        uninstall_object(thd, *it);
        thd->clear_error();
      }
      error.raise();
    }
  }
  if (failed) {
    remove_tree(version_dir);
    rmdir(package_dir.c_str());
    return true;
  }

  LogErr(INFORMATION_LEVEL, ER_PACKAGE_LOG_OPERATION, name.c_str(),
         row.version.c_str(), "installed", registry.c_str(),
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
  const Package_row &row = installed[0];
  {
    const Package_security_guard security_guard(thd);
    const Disable_binlog_guard binlog_guard(thd);
    for (auto it = row.objects.rbegin(); it != row.objects.rend(); ++it)
      if (uninstall_object(thd, *it)) return true;
    if (write_package(thd, row, true)) return true;
  }
  remove_tree(store_path(name));
  LogErr(INFORMATION_LEVEL, ER_PACKAGE_LOG_OPERATION, name.c_str(),
         row.version.c_str(), "uninstalled", row.registry.c_str(),
         row.compat_key.c_str(), row.sha256.c_str());
  my_ok(thd);
  return false;
}

bool Sql_cmd_show_packages::execute(THD *thd) {
  std::vector<Package_row> rows;
  {
    const Package_security_guard security_guard(thd);
    if (read_packages(thd, "", &rows)) return true;
  }

  mem_root_deque<Item *> fields(thd->mem_root);
  for (const char *column : {"Package", "Version", "Constraint", "Origin",
                             "Objects", "Compat_key", "Registry"})
    fields.push_back(new Item_empty_string(column, NAME_CHAR_LEN));
  if (thd->send_result_metadata(fields,
                                Protocol::SEND_NUM_ROWS | Protocol::SEND_EOF))
    return true;

  Protocol *protocol = thd->get_protocol();
  for (const Package_row &row : rows) {
    std::string objects;
    for (const Package_object &object : row.objects)
      objects +=
          (objects.empty() ? "" : ", ") + object.type + " " + object.name;
    protocol->start_row();
    for (const std::string *value : std::initializer_list<const std::string *>{
             &row.name, &row.version, &row.constraint, &row.origin, &objects,
             &row.compat_key, &row.registry})
      protocol->store_string(value->c_str(), value->length(),
                             system_charset_info);
    if (protocol->end_row()) return true;
  }
  my_eof(thd);
  return false;
}
