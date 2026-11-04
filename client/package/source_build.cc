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

#include "client/package/source_build.h"

#include <cerrno>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>

#ifndef _WIN32
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace package_build {

namespace {

constexpr size_t log_tail_length = 400;

std::string log_tail(const std::string &path) {
  std::ifstream in(path);
  std::stringstream content;
  content << in.rdbuf();
  std::string text = content.str();
  if (text.size() > log_tail_length)
    text = text.substr(text.size() - log_tail_length);
  for (char &c : text)
    if (c == '\n' || c == '\r' || c == '\t') c = ' ';
  return text;
}

bool helper_failed(const std::string &why, Failure *failure) {
  failure->error = "ER_PACKAGE_HELPER_FAILED";
  failure->args = {why};
  return false;
}

}  // namespace

#ifndef _WIN32
int run_program(const std::vector<std::string> &argv, const std::string &cwd,
                const std::vector<std::string> &env, unsigned timeout,
                const std::string &log_path, bool *timed_out) {
  *timed_out = false;
  const pid_t pid = fork();
  if (pid < 0) return -1;
  if (pid == 0) {
    setpgid(0, 0);
    const int log = open(log_path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (log >= 0) {
      dup2(log, STDOUT_FILENO);
      dup2(log, STDERR_FILENO);
      close(log);
    }
    if (!cwd.empty() && chdir(cwd.c_str()) != 0) _exit(127);
    for (const std::string &setting : env)
      putenv(const_cast<char *>(setting.c_str()));
    std::vector<char *> args;
    for (const std::string &arg : argv)
      args.push_back(const_cast<char *>(arg.c_str()));
    args.push_back(nullptr);
    execvp(args[0], args.data());
    _exit(127);
  }
  setpgid(pid, pid);

  const time_t deadline = time(nullptr) + timeout;
  int status = 0;
  for (;;) {
    const pid_t done = waitpid(pid, &status, WNOHANG);
    if (done == pid) break;
    if (done < 0 && errno != EINTR) return -1;
    if (time(nullptr) >= deadline) {
      kill(-pid, SIGKILL);
      waitpid(pid, &status, 0);
      *timed_out = true;
      return -1;
    }
    usleep(100000);
  }
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}
#else
int run_program(const std::vector<std::string> &, const std::string &,
                const std::vector<std::string> &, unsigned, const std::string &,
                bool *timed_out) {
  *timed_out = false;
  return -1;
}
#endif

bool build_from_source(const Manifest &manifest, const std::string &sdk_prefix,
                       const std::string &build_type,
                       const std::string &work_dir, const std::string &artifact,
                       unsigned timeout, Failure *failure) {
#ifdef _WIN32
  return helper_failed("source builds are not supported on Windows", failure);
#else
  namespace fs = std::filesystem;
  const Source &source = manifest.source;
  const std::string tree = work_dir + "/src";
  const std::string clone_log = work_dir + "/clone.log";
  const std::string log = work_dir + "/build.log";
  const time_t started = time(nullptr);
  auto remaining = [&]() {
    const time_t used = time(nullptr) - started;
    return used >= static_cast<time_t>(timeout)
               ? 1u
               : static_cast<unsigned>(timeout - used);
  };

  bool timed_out = false;
  if (run_program({"git", "-c", "advice.detachedHead=false", "clone", "--quiet",
                   "--depth", "1", "--branch", source.tag, source.git, tree},
                  "", {}, remaining(), clone_log, &timed_out) != 0)
    return helper_failed(timed_out
                             ? "source checkout timed out"
                             : "cannot clone " + source.git + " at " +
                                   source.tag + ": " + log_tail(clone_log),
                         failure);

  const std::string head_file = work_dir + "/head";
  if (run_program({"sh", "-c", "git rev-parse HEAD > \"$0\"", head_file}, tree,
                  {}, remaining(), clone_log, &timed_out) != 0)
    return helper_failed("cannot read the checked out commit", failure);
  std::string head;
  std::ifstream(head_file) >> head;
  if (head != source.commit)
    return helper_failed("tag " + source.tag + " is at " + head +
                             ", not the pinned commit " + source.commit,
                         failure);

  if (source.produces.find("..") != std::string::npos ||
      source.produces.front() == '/')
    return helper_failed("[source] produces must be a path inside the tree",
                         failure);

  const std::vector<std::string> env = {
      "MYSQL_SDK_PREFIX=" + sdk_prefix,
      "CMAKE_PREFIX_PATH=" + sdk_prefix,
  };
  const std::string cmake_type = build_type == "debug" ? "Debug" : "Release";
  int status = run_program(
      {"cmake", "-S", ".", "-B", "build", "-DCMAKE_BUILD_TYPE=" + cmake_type,
       "-DCMAKE_PREFIX_PATH=" + sdk_prefix},
      tree, env, remaining(), log, &timed_out);
  if (status == 0 && !timed_out)
    status = run_program({"cmake", "--build", "build"}, tree, env, remaining(),
                         log, &timed_out);
  if (timed_out)
    return helper_failed(
        "source build timed out after " + std::to_string(timeout) + " s",
        failure);
  if (status != 0)
    return helper_failed("source build exited with status " +
                             std::to_string(status) + ": " + log_tail(log),
                         failure);

  const fs::path produced = fs::path(tree) / source.produces;
  std::error_code ec;
  if (!fs::is_regular_file(produced, ec))
    return helper_failed("source build did not produce " + source.produces,
                         failure);
  fs::copy_file(produced, artifact, fs::copy_options::overwrite_existing, ec);
  if (ec) return helper_failed("cannot stage " + artifact, failure);
  return true;
#endif
}

}  // namespace package_build
