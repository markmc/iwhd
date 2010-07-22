#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([repod],[1.0])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

AC_CHECK_LIB([curl], [curl_easy_init],
	CURL_LIB=-lcurl,
	[AC_MSG_ERROR([Missing required CURL lib])])
AC_SUBST(CURL_LIB)

AC_CHECK_LIB([jansson], [json_object_get],
	JANSSON_LIB=-ljansson,
	[AC_MSG_ERROR([Missing required Jansson lib])])
AC_SUBST(JANSSON_LIB)

AC_CHECK_LIB([microhttpd], [MHD_start_daemon],
	UHTTPD_LIB=-lmicrohttpd,
	[AC_MSG_ERROR([Missing required microhttpd lib])])
AC_SUBST(UHTTPD_LIB)

AC_CHECK_LIB([pthread], [pthread_create],
	PTHREAD_LIB=-lpthread,
	[AC_MSG_ERROR([Missing required pthread lib])])
AC_SUBST(PTHREAD_LIB)

AC_CHECK_LIB([glib-2.0], [g_hash_table_new_full],
	GLIB2_LIB=-lglib-2.0,
	[AC_MSG_ERROR([Missing required glib2 lib])])
AC_SUBST(GLIB2_LIB)

PKG_CHECK_MODULES([HAIL],[libhail >= 0.8])
AC_SUBST(HAIL_LIBS)
AC_SUBST(HAIL_CFLAGS)

AC_CHECK_LIB([crypto], [OPENSSL_init_library],
	CRYPTO_LIB=-lcrypto,
	[AC_MSG_ERROR([Missing required crypto lib])])
AC_SUBST(CRYPTO_LIB)

AC_CHECK_LIB([xml2], [xmlInitParser],
	XML2_LIB=-lxml2,
	[AC_MSG_ERROR([Missing required XML2 lib])])
AC_SUBST(XML2_LIB)

# Mongo builds a static lib (how 80s of them) so we have to deal with the
# dependencies for that as well.
#AC_CHECK_LIB([mongoclient], [_ZN5mongo3OID4initEv])

AC_CHECK_LIB([boost_filesystem-mt], [_ZN5boost10filesystem6detail6throwsE],
	BOOST_FS_LIB=-lboost_filesystem-mt,
	[AC_MSG_ERROR([Missing required boost_filesystem lib])])
AC_SUBST(BOOST_FS_LIB)

AC_CHECK_LIB([boost_program_options-mt], [_ZN5boost15program_options11bool_switchEv],
	BOOST_PO_LIB=-lboost_program_options-mt,
	[AC_MSG_ERROR([Missing required boost_program_options lib])])
AC_SUBST(BOOST_PO_LIB)

AC_CHECK_LIB([boost_system-mt], [_ZN5boost6system6throwsE],
	BOOST_SYS_LIB=-lboost_system-mt,
	[AC_MSG_ERROR([Missing required boost_system lib])])
AC_SUBST(BOOST_SYS_LIB)

AC_CHECK_LIB([boost_thread-mt], [_ZN5boost6detail12get_tss_dataEPKv],
	BOOST_THR_LIB=-lboost_thread-mt,
	[AC_MSG_ERROR([Missing required boost_thread lib])])
AC_SUBST(BOOST_THR_LIB)


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

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
