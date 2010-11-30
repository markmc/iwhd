#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# Copyright (C) 1991, 1993-2010 Red Hat, Inc.

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

AC_PREREQ([2.65])
AC_INIT([iwhd], [1.0], [iwhd-devel@fedorahosted.org])
AC_CONFIG_AUX_DIR([build-aux])

AC_CONFIG_HEADERS([config.h:config.hin])
AM_INIT_AUTOMAKE([1.11.1 color-tests parallel-tests])
AM_SILENT_RULES([yes]) # make --enable-silent-rules the default.

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AM_PROG_CC_C_O
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

AC_CHECK_LIB([glib-2.0], [g_hash_table_new_full],
	[GLIB2_LIB=-lglib-2.0],
	[AC_MSG_ERROR([Missing required glib2 lib])])
AC_SUBST([GLIB2_LIB])

PKG_CHECK_MODULES([HAIL],[libhail >= 0.8])
AC_SUBST([HAIL_LIBS])
AC_SUBST([HAIL_CFLAGS])

AC_CHECK_LIB([xml2], [xmlInitParser],
	[XML2_LIB=-lxml2],
	[AC_MSG_ERROR([Missing required XML2 lib])])
AC_SUBST([XML2_LIB])

# from http://www.gnu.org/software/autoconf-archive/
AX_BOOST_BASE
AX_BOOST_SYSTEM
AX_BOOST_THREAD

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h strings.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([gettimeofday memmove memset strcasecmp strdup strndup strtoul])

AC_CONFIG_FILES([
Makefile
t/Makefile
man/Makefile
])
AC_OUTPUT
