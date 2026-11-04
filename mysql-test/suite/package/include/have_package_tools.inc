# Skip unless the package helper, the registry tool, python3 with tomllib
# and the openssl command are all available.
--source include/not_windows.inc
--disable_query_log
perl;
  my $ok = $ENV{MYSQL_PACKAGE_BUILD} && $ENV{MYSQL_PACKAGE_REGISTRY} &&
    system("python3 -c 'import tomllib' >/dev/null 2>&1") == 0 &&
    system("openssl version >/dev/null 2>&1") == 0;
  open(my $f, '>', "$ENV{MYSQLTEST_VARDIR}/tmp/have_package_tools.inc")
    or die;
  print $f ($ok ? "" :
    "--skip needs mysql_package_build, python3 with tomllib and openssl\n");
  close $f;
EOF
--source $MYSQLTEST_VARDIR/tmp/have_package_tools.inc
--remove_file $MYSQLTEST_VARDIR/tmp/have_package_tools.inc
--enable_query_log
