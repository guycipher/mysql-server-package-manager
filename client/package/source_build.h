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

#ifndef CLIENT_PACKAGE_SOURCE_BUILD_H
#define CLIENT_PACKAGE_SOURCE_BUILD_H

/**
  @file client/package/source_build.h

  Building a package from its pinned source against the installed SDK.
*/

#include <string>
#include <vector>

#include "client/package/registry.h"

namespace package_build {

/**
  Run a program with a time limit, in its own process group so a timeout
  stops everything it started. Output goes to log_path.

  @return the exit status, or -1 if it could not run or timed out.
*/
int run_program(const std::vector<std::string> &argv, const std::string &cwd,
                const std::vector<std::string> &env, unsigned timeout,
                const std::string &log_path, bool *timed_out);

/**
  Clone the manifest's source at its tag, check the tag points at the pinned
  commit, run the build recipe and copy what it produces to artifact.

  The only recipe is cmake, which configures the tree against the SDK with
  the build type of the server, release or debug, and builds it.
*/
bool build_from_source(const Manifest &manifest, const std::string &sdk_prefix,
                       const std::string &build_type,
                       const std::string &work_dir, const std::string &artifact,
                       unsigned timeout, Failure *failure);

}  // namespace package_build

#endif  // CLIENT_PACKAGE_SOURCE_BUILD_H
