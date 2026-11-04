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

#ifndef SQL_PACKAGE_SQL_PACKAGE_H
#define SQL_PACKAGE_SQL_PACKAGE_H

/**
  @file sql/package/sql_package.h

  INSTALL PACKAGE, UPGRADE PACKAGE, UNINSTALL PACKAGE and SHOW PACKAGES.
*/

#include "lex_string.h"
#include "my_sqlcommand.h"
#include "sql/sql_cmd.h"

class THD;

/**
  INSTALL PACKAGE 'name' [VERSION 'constraint'] [FROM 'registry']

  Resolves the package through the helper, verifies the staged artifact
  against the trust roots, and installs every plugin, function and component
  it lists, all of them or none.
*/
class Sql_cmd_install_package : public Sql_cmd {
 public:
  Sql_cmd_install_package(const LEX_CSTRING &name,
                          const LEX_CSTRING &constraint,
                          const LEX_CSTRING &registry)
      : m_name(name), m_constraint(constraint), m_registry(registry) {}

  enum_sql_command sql_command_code() const override {
    return SQLCOM_INSTALL_PACKAGE;
  }

  bool execute(THD *thd) override;

 private:
  const LEX_CSTRING m_name;
  const LEX_CSTRING m_constraint;
  const LEX_CSTRING m_registry;
};

/**
  UPGRADE PACKAGE 'name' [VERSION 'constraint']

  Resolves the newest version under the recorded constraint, or under a new
  one that is then recorded, from the registry the package came from. The
  previous version stays in the store until the new one is installed, and is
  installed again if it fails. When tables use a storage engine of the
  package, the new version is staged and replaces it at the next restart.
*/
class Sql_cmd_upgrade_package : public Sql_cmd {
 public:
  Sql_cmd_upgrade_package(const LEX_CSTRING &name,
                          const LEX_CSTRING &constraint)
      : m_name(name), m_constraint(constraint) {}

  enum_sql_command sql_command_code() const override {
    return SQLCOM_UPGRADE_PACKAGE;
  }

  bool execute(THD *thd) override;

 private:
  const LEX_CSTRING m_name;
  const LEX_CSTRING m_constraint;
};

/** UNINSTALL PACKAGE 'name', which removes everything the package installed. */
class Sql_cmd_uninstall_package : public Sql_cmd {
 public:
  explicit Sql_cmd_uninstall_package(const LEX_CSTRING &name) : m_name(name) {}

  enum_sql_command sql_command_code() const override {
    return SQLCOM_UNINSTALL_PACKAGE;
  }

  bool execute(THD *thd) override;

 private:
  const LEX_CSTRING m_name;
};

/** SHOW PACKAGES, which needs no privilege, like SHOW PLUGINS. */
class Sql_cmd_show_packages : public Sql_cmd {
 public:
  enum_sql_command sql_command_code() const override {
    return SQLCOM_SHOW_PACKAGES;
  }

  bool execute(THD *thd) override;
};

/**
  Applies the versions UPGRADE PACKAGE staged for restart, before the
  plugins in mysql.plugin are loaded. A staged version is verified again and
  is discarded, with a warning in the error log, if it no longer passes.
*/
void package_apply_pending();

#endif /* SQL_PACKAGE_SQL_PACKAGE_H */
