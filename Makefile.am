# Copyright (C) 2010 Red Hat, Inc.

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

AM_CFLAGS = -W -Wall -Wextra -Wno-unused -Wformat-security \
  -Wp,-D_FORTIFY_SOURCE=2 -O2 -fdiagnostics-show-option

AM_CPPFLAGS	= -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include

iwhd_YFLAGS = -d

SUBDIRS = t
ACLOCAL_AMFLAGS = -I ax

# iwhd is short for Image WareHouse Daemon.
bin_PROGRAMS = iwhd

EXTRA_DIST =		\
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

MOSTLYCLEANFILES += iwhd.spec
MAINTAINERCLEANFILES += iwhd.spec
iwhd.spec: iwhd.spec.in Makefile.am
	rm -f $@-t $@
	sed 's/@''VERSION@/$(VERSION)/' $< > $@-t
	chmod a=r $@-t
	mv $@-t $@

.PHONY: rpm
rpm: dist iwhd.spec
	chmod 644 $(distdir).tar.gz
	rpmbuild -ta $(distdir).tar.gz

iwhd_CPPFLAGS	= $(HAIL_CFLAGS)
iwhd_LDADD =		\
  -lmongoclient		\
  $(BOOST_SYSTEM_LIB)	\
  $(BOOST_THREAD_LIB)	\
  $(CRYPTO_LIB)		\
  $(CURL_LIB)		\
  $(JANSSON_LIB)	\
  $(UHTTPD_LIB)		\
  $(PTHREAD_LIB)	\
  $(XML2_LIB)		\
  $(GLIB2_LIB)		\
  $(HAIL_LIBS)

MOSTLYCLEANFILES += qlexer.c
MAINTAINERCLEANFILES += qlexer.c
EXTRA_DIST += qlexer.c
