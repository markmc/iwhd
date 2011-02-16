dnl ==========================================================================
dnl find libxml2 compile and link flags, derived from code in libvirt
dnl ==========================================================================

# gl_LIBXML2([MINIMUM_VERSION])
# -----------------------------
AC_DEFUN([gl_LIBXML2],
[
  gl_xml_min_ver=$1
  gl_xml_config=xml2-config
  gl_libxml_found=no
  LIBXML_CFLAGS=
  LIBXML_LIBS=

  AC_ARG_WITH([libxml], AC_HELP_STRING([--with-libxml=@<:@PFX@:>@],
	      [libxml2 location]))
  if test "x$with_libxml" = "xno"; then
      AC_MSG_CHECKING(for libxml2 libraries >= $gl_xml_min_ver)
      AC_MSG_ERROR([libxml2 >= $gl_xml_min_ver is required])
  fi

  if test "$gl_libxml_found" = no; then
      if test "x$with_libxml" != x; then
	  gl_xml_config=$with_libxml/bin/$gl_xml_config
      fi
      AC_MSG_CHECKING([libxml2 $gl_xml_config >= $gl_xml_min_ver])
      if ! $gl_xml_config --version > /dev/null 2>&1; then
	  AC_MSG_ERROR([Could not find libxml2 (see config.log for details).])
      fi
      gl_ver=`$gl_xml_config --version |
	  awk -F. '{ printf "%d", ([$]1 * 1000 + [$]2) * 1000 + [$]3}'`
      gl_min_ver=`echo $gl_xml_min_ver |
	  awk -F. '{ printf "%d", ([$]1 * 1000 + [$]2) * 1000 + [$]3}'`
      if test "$gl_ver" -ge "$gl_min_ver"; then
	  LIBXML_LIBS="`$gl_xml_config --libs`"
	  LIBXML_CFLAGS="`$gl_xml_config --cflags`"
	  gl_libxml_found=yes
	  AC_MSG_RESULT([yes])
      else
	  AC_MSG_ERROR([You need at least libxml2 $gl_xml_min_ver])
      fi
  fi

  AC_SUBST([LIBXML_CFLAGS])
  AC_SUBST([LIBXML_LIBS])
])
