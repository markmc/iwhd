## Process this file with automake to create Makefile.in
# Copyright 2010-2011 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

TESTS =						\
  parse-test					\
  basic						\
  creation-code					\
  exercise					\
  provider					\
  replication					\
  auto						\
  registration

lock_dir = $(abs_builddir)/lock-dir
clean-local:
	$(AM_V_GEN)rm -rf "$(lock_dir)"

.PHONY: prereq
prereq:
	$(AM_V_GEN)rm -rf "$(lock_dir)" && mkdir "$(lock_dir)"

$(TEST_LOGS): prereq

EXTRA_DIST =					\
  $(TESTS)					\
  init.cfg					\
  init.sh

TESTS_ENVIRONMENT =				\
  tmp__=$$TMPDIR; test -d "$$tmp__" || tmp__=.; \
  TMPDIR=$$tmp__; export TMPDIR;		\
  exec 9>&2;					\
  shell_or_perl_() {				\
    if grep '^\#!/usr/bin/perl' "$$1" > /dev/null; then			\
      if $(PERL) -e 'use warnings' > /dev/null 2>&1; then		\
	grep '^\#!/usr/bin/perl -T' "$$1" > /dev/null && T_=T || T_=;	\
	$(PERL) -w$$T_ -I$(srcdir) -MCoreutils				\
	      -M"CuTmpdir qw($$f)" -- "$$1";	\
      else					\
	echo 1>&2 "$$tst: configure did not find a usable version of Perl," \
	  "so skipping this test";		\
	(exit 77);				\
      fi;					\
    else					\
      $(SHELL) "$$1";				\
    fi;						\
  };						\
  export					\
  LC_ALL=C					\
  VERSION=$(VERSION)				\
  abs_top_builddir='$(abs_top_builddir)'	\
  abs_top_srcdir='$(abs_top_srcdir)'		\
  abs_srcdir='$(abs_srcdir)'			\
  built_programs='$(built_programs)'		\
  lock_dir='$(lock_dir)'			\
  srcdir='$(srcdir)'				\
  top_srcdir='$(top_srcdir)'			\
  CC='$(CC)'					\
  IWHD_TEST_NAME=`echo $$tst|sed 's,^\./,,;s,/,-,g'` \
  MALLOC_PERTURB_=$(MALLOC_PERTURB_); export MALLOC_PERTURB_ \
  PACKAGE_BUGREPORT='$(PACKAGE_BUGREPORT)'	\
  PACKAGE_VERSION=$(PACKAGE_VERSION)		\
  PERL='$(PERL)'				\
  SHELL='$(SHELL)'				\
  PATH='$(abs_top_builddir)$(PATH_SEPARATOR)'"$$PATH" \
  ; shell_or_perl_
