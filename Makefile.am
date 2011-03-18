# Copyright (C) 2010-2011 Red Hat, Inc.

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

AM_CFLAGS = $(WARN_CFLAGS) $(WERROR_CFLAGS)

AM_YFLAGS = -d

SUBDIRS = lib . gnulib-tests t man
ACLOCAL_AMFLAGS = -I m4

# iwhd is short for Image WareHouse Daemon.
bin_PROGRAMS = iwhd dc-rhev-image

EXTRA_DIST =		\
  iwhd.init.in		\
  iwhd-qparser.h	\
  iwhd.spec		\
  iwhd.spec.in

BUILT_SOURCES = iwhd-qparser.h qlexer.c

MOSTLYCLEANFILES =
MAINTAINERCLEANFILES =

iwhd_SOURCES = \
  auto.c	\
  backend.c	\
  backend.h	\
  gc-wrap.h	\
  iwh.h		\
  meta.cpp	\
  meta.h	\
  mpipe.c	\
  mpipe.h	\
  replica.c	\
  replica.h	\
  qparser.y	\
  query.h	\
  rest.c	\
  setup.c	\
  setup.h	\
  state_defs.h	\
  template.c	\
  template.h

EXTRA_iwhd_SOURCES = qlexer.l

dc_rhev_image_SOURCES = dc-rhev-image.c

VERSION_no_hyphen = $$(echo $(VERSION)|tr - _)

MOSTLYCLEANFILES += iwhd.spec
MAINTAINERCLEANFILES += iwhd.spec
iwhd.spec: iwhd.spec.in Makefile
	$(AM_V_GEN)rm -f $@-t $@
	$(AM_V_at)v=$$(echo $(VERSION)|tr - .); \
	  sed 's/[@]VERSION@/'"$$v"/ $< > $@-t
	$(AM_V_at)chmod a=r $@-t
	$(AM_V_at)mv $@-t $@

# The following rule accommodates pre-release version number strings
# like "0.0.273-1621" that contain a "-".  Repack the tarball
# to one with "." substituted for any - in the version string.
.PHONY: rpm
rpm: dist iwhd.spec
	chmod 644 $(distdir).tar.gz
	case $(VERSION) in					\
	  *-*)							\
	    v=$$(echo $(VERSION)|tr - .);			\
	    base=$(PACKAGE)-$$v;				\
	    tgz=$$base.tar.gz;					\
	    tar xf $(distdir).tar.gz				\
	      && rm -rf $$base $$tgz				\
	      && mv $(distdir) $$base				\
	      && tar -czf - $$base > $$tgz			\
	      && rpmbuild -ta $$tgz; e=$$?			\
	    rm -rf $$base $$tgz;				\
	    exit $$e						\
	    ;;							\
	  *) rpmbuild -ta $(distdir).tar.gz ;;			\
	esac

# Use this directory for the local FS-based store mentioned in the etc config.
DEFAULT_FS_DIR = $(localstatedir)/lib/iwhd

DISTCLEANFILES = iwhd.init
iwhd.init: iwhd.init.in $(top_builddir)/config.status
	$(AM_V_GEN)sed						\
	    -e s!@localstatedir\@!@localstatedir@!g		\
	    -e s!@sbindir\@!@sbindir@!g				\
	    -e s!@sysconfdir\@!@sysconfdir@!g			\
	  < $< > $@-t &&					\
	chmod a+x $@-t &&					\
	mv $@-t $@

DISTCLEANFILES += iwhd-conf.js
iwhd-conf.js: $(top_builddir)/config.status
	$(AM_V_GEN)printf '%s\n'				\
	    '['							\
	    '  {'						\
	    '    "name": "primary",'				\
	    '    "type": "fs",'					\
	    '    "path": "$(DEFAULT_FS_DIR)"'			\
	    '  }'						\
	    ']'							\
	  > $@-t && chmod a-w $@-t && mv $@-t $@

.PHONY: install-data-local
install-data-local: iwhd.init iwhd-conf.js
	mkdir -p $(DESTDIR)$(sysconfdir)/rc.d/init.d
	$(INSTALL_SCRIPT) iwhd.init $(DESTDIR)$(sysconfdir)/rc.d/init.d/iwhd
	mkdir -p $(DESTDIR)$(sysconfdir)/iwhd
	$(INSTALL_DATA) iwhd-conf.js $(DESTDIR)$(sysconfdir)/iwhd/conf.js
	mkdir -p $(DESTDIR)$(DEFAULT_FS_DIR)

.PHONY: uninstall-local
uninstall-local:
	rm -f $(DESTDIR)$(sysconfdir)/rc.d/init.d/iwhd \
	  $(DESTDIR)$(sysconfdir)/iwhd/conf.js
	rmdir $(DESTDIR)$(DEFAULT_FS_DIR)

AM_CPPFLAGS = $(HAIL_CFLAGS) -I$(top_srcdir)/lib
iwhd_LDADD =		\
  lib/libiwhd.a		\
  -lgc -lpthread	\
  -lmongoclient		\
  $(BOOST_SYSTEM_LIB)	\
  $(BOOST_THREAD_LIB)	\
  $(CURL_LIB)		\
  $(JANSSON_LIB)	\
  $(UHTTPD_LIB)		\
  $(PTHREAD_LIB)	\
  $(HAIL_LIBS)

dc_rhev_image_CPPFLAGS = $(LIBXML_CFLAGS) -I$(top_srcdir)/lib
dc_rhev_image_LDADD =	\
  lib/libiwhd.a		\
  $(LIB_ACL)		\
  $(CURL_LIB)		\
  $(JANSSON_LIB)	\
  $(LIBXML_LIBS)	\
  $(UUID_LIB)

MOSTLYCLEANFILES += qlexer.c
MAINTAINERCLEANFILES += qlexer.c
EXTRA_DIST += qlexer.c

noinst_PROGRAMS = parser-test
BUILT_SOURCES += parser-test.c
MAINTAINERCLEANFILES += $(BUILT_SOURCES)
parser_test_CPPFLAGS	= -I$(top_srcdir)/lib
parser_test_LDADD = lib/libiwhd.a -lgc -lpthread

parser-test.c: Makefile.am
	rm -f $@-t $@
	printf '#define PARSER_UNIT_TEST 1\n' > $@-t
	printf '#include "qparser.c"\n' >> $@-t
	chmod a=r $@-t
	mv $@-t $@
