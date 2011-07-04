#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# Copyright (C) 1991, 1993-2011 Red Hat, Inc.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

AC_INIT([iwhd],
        m4_esyscmd([build-aux/git-version-gen .tarball-version]),
        [iwhd-devel@fedorahosted.org])
AC_CONFIG_AUX_DIR([build-aux])

AC_CONFIG_HEADERS([config.h:config.hin])
AM_INIT_AUTOMAKE([1.11.1 dist-xz color-tests parallel-tests])
AM_SILENT_RULES([yes]) # make --enable-silent-rules the default.

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AM_PROG_CC_C_O
gl_EARLY

# Maintainer note - comment this line out if you plan to rerun
# GNULIB_POSIXCHECK testing to see if M4 should be using more modules.
# Leave it uncommented for normal releases, for faster ./configure.
gl_ASSERT_NO_GNULIB_POSIXCHECK

AC_PROG_RANLIB
AC_TYPE_UINT64_T

gl_INIT

AC_PROG_YACC
AC_PROG_LEX
AM_MISSING_PROG([HELP2MAN], [help2man])

AC_CHECK_LIB([curl], [curl_easy_init],
	[CURL_LIB=-lcurl],
	[AC_MSG_ERROR([Missing required CURL lib])])
AC_SUBST([CURL_LIB])

AC_CHECK_LIB([jansson], [json_object_get],
	[JANSSON_LIB=-ljansson],
	[AC_MSG_ERROR([Missing required Jansson lib])])
AC_SUBST([JANSSON_LIB])

AC_CHECK_LIB([microhttpd], [MHD_start_daemon],
	[UHTTPD_LIB=-lmicrohttpd],
	[AC_MSG_ERROR([Missing required microhttpd lib])])
AC_SUBST([UHTTPD_LIB])

AC_CHECK_LIB([pthread], [pthread_create],
	[PTHREAD_LIB=-lpthread],
	[AC_MSG_ERROR([Missing required pthread lib])])
AC_SUBST([PTHREAD_LIB])

AC_CHECK_LIB([uuid], [uuid_generate_random],
	[UUID_LIB=-luuid],
	[AC_MSG_ERROR([Missing required uuid lib])])
AC_SUBST([UUID_LIB])

PKG_CHECK_MODULES([HAIL],[libhail >= 0.8])
AC_SUBST([HAIL_LIBS])
AC_SUBST([HAIL_CFLAGS])

gl_LIBXML2([2.6.0])

AC_CHECK_HEADER([gc.h], ,
  [AC_MSG_ERROR([Missing GC development library: gc-devel or libgc-dev])])

AC_LANG_PUSH([C++])
AC_CHECK_HEADER([mongo/client/dbclient.h], ,
  [AC_MSG_ERROR([Missing Mongo DB client development library: mongodb-devel])],
  [#undef VERSION])
AC_LANG_POP

# Starting in jansson 2.1, file-loading functions require an
# additional "flags" argument.  Test for this.
AC_CACHE_CHECK([whether json_load_file takes 3 arguments],
  [iw_cv_func_jansson_flag],
  [AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
    #include <jansson.h>
    json_t *f (void) { return json_load_file ("file", 0, NULL); }]])],
      [iw_cv_func_jansson_flag=0,],
      [iw_cv_func_jansson_flag=])])
AC_DEFINE_UNQUOTED([JANSSON_LOAD_FLAG], $iw_cv_func_jansson_flag,
  [Define to "0," if json_load_file and json_loads require a flags arguments.])

# from http://www.gnu.org/software/autoconf-archive/
AX_BOOST_BASE
AX_BOOST_SYSTEM
AX_BOOST_THREAD

AC_ARG_ENABLE([gcc-warnings],
  [AS_HELP_STRING([--enable-gcc-warnings],
                  [turn on lots of GCC warnings (for developers)])],
  [case $enableval in
     yes|no) ;;
     *)      AC_MSG_ERROR([bad value $enableval for gcc-warnings option]) ;;
   esac
   gl_gcc_warnings=$enableval],
  [gl_gcc_warnings=no]
)

if test "$gl_gcc_warnings" = yes; then
  gl_WARN_ADD([-Werror], [WERROR_CFLAGS])
  AC_SUBST([WERROR_CFLAGS])

  nw=
  # This, $nw, is the list of warnings we disable.
  nw="$nw -Wdeclaration-after-statement" # too useful to forbid
  nw="$nw -Waggregate-return"       # anachronistic
  nw="$nw -Wlong-long"              # C90 is anachronistic (lib/gethrxtime.h)
  nw="$nw -Wc++-compat"             # We don't care about C++ compilers
  nw="$nw -Wundef"                  # Warns on '#if GNULIB_FOO' etc in gnulib
  nw="$nw -Wtraditional"            # Warns on #elif which we use often
  nw="$nw -Wcast-qual"              # Too many warnings for now
  nw="$nw -Wconversion"             # Too many warnings for now
  nw="$nw -Wsystem-headers"         # Don't let system headers trigger warnings
  nw="$nw -Wsign-conversion"        # Too many warnings for now
  nw="$nw -Wtraditional-conversion" # Too many warnings for now
  nw="$nw -Wunreachable-code"       # Too many warnings for now
  nw="$nw -Wunused-macros"          # bison-generated
  nw="$nw -Wpadded"                 # Our structs are not padded
  nw="$nw -Wredundant-decls"        # openat.h declares e.g., mkdirat
  nw="$nw -Wlogical-op"             # any use of fwrite provokes this
  nw="$nw -Wformat-nonliteral"      # who.c and pinky.c strftime uses
  nw="$nw -Wvla"                    # warnings in gettext.h
  nw="$nw -Wnested-externs"         # use of XARGMATCH/verify_function__
  nw="$nw -Wswitch-enum"            # Too many warnings for now
  nw="$nw -Wswitch-default"         # Too many warnings for now
  nw="$nw -Wstack-protector"        # not worth working around
  nw="$nw -Wstrict-overflow"        # in bison-generated code
  nw="$nw -Wunsafe-loop-optimizations" # in bison-generated code
  nw="$nw -Wmissing-noreturn"       # yy_fatal_error in flex-generated code
  nw="$nw -Winline"                 # setup.h's kv_hash_insert_new

  gl_MANYWARN_ALL_GCC([ws])
  gl_MANYWARN_COMPLEMENT([ws], [$ws], [$nw])
  for w in $ws; do
    gl_WARN_ADD([$w])
  done
  gl_WARN_ADD([-Wno-unused-function])
  gl_WARN_ADD([-Wno-unused-parameter]) # Too many warnings for now

  # In spite of excluding -Wlogical-op above, it is enabled, as of
  # gcc 4.5.0 20090517, and it provokes warnings in cat.c, dd.c, truncate.c
  gl_WARN_ADD([-Wno-logical-op])

  gl_WARN_ADD([-fdiagnostics-show-option])
  gl_WARN_ADD([-funit-at-a-time])

  AC_SUBST([WARN_CFLAGS])

  AC_DEFINE([lint], [1], [Define to 1 if the compiler is checking for lint.])
  AC_DEFINE([_FORTIFY_SOURCE], [2],
    [enable compile-time and run-time bounds-checking, and some warnings])
  AC_DEFINE([GNULIB_PORTCHECK], [1], [enable some gnulib portability checks])

  # We use a slightly smaller set of warning options for lib/.
  # Remove the following and save the result in GNULIB_WARN_CFLAGS.
  nw=
  nw="$nw -Wuninitialized"
  nw="$nw -Wmissing-prototypes"
  nw="$nw -Wold-style-definition"
  gl_MANYWARN_COMPLEMENT([GNULIB_WARN_CFLAGS], [$WARN_CFLAGS], [$nw])
  AC_SUBST([GNULIB_WARN_CFLAGS])

  # For gnulib-tests, the set is slightly smaller still.
  nw=
  nw="$nw -Wstrict-prototypes"
  gl_MANYWARN_COMPLEMENT([GNULIB_TEST_WARN_CFLAGS],
                         [$GNULIB_WARN_CFLAGS], [$nw])
  AC_SUBST([GNULIB_TEST_WARN_CFLAGS])
fi

AM_GNU_GETTEXT([external], [need-ngettext])
AM_GNU_GETTEXT_VERSION([0.17])

AC_CONFIG_FILES([
Makefile
gnulib-tests/Makefile
lib/Makefile
man/Makefile
t/Makefile
po/Makefile.in
])
AC_OUTPUT
