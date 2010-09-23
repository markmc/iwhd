# Copyright (C) 2010 Free Software Foundation, Inc.

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

AM_CFLAGS = -W -Wall -Wextra -Wno-unused \
  -Wp,-D_FORTIFY_SOURCE=2 -O2 -fdiagnostics-show-option

AM_CPPFLAGS	= -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include

bin_PROGRAMS = iwhd
EXTRA_DIST = query.leg

# iwhd is short for Image WareHouse Daemon.

iwhd_SOURCES = \
  backend.c	\
  backend.h	\
  iwh.h		\
  meta.cpp	\
  meta.h	\
  mpipe.c	\
  mpipe.h	\
  proxy.c	\
  proxy.h	\
  query.c	\
  query.h	\
  rest.c	\
  state_defs.h	\
  template.c	\
  template.h

iwhd_CPPFLAGS	= $(HAIL_CFLAGS)
iwhd_LDADD =		\
  -lmongoclient		\
  $(BOOST_FS_LIB)	\
  $(BOOST_PO_LIB)	\
  $(BOOST_SYS_LIB)	\
  $(BOOST_THR_LIB)	\
  $(CRYPTO_LIB)		\
  $(CURL_LIB)		\
  $(JANSSON_LIB)	\
  $(UHTTPD_LIB)		\
  $(PTHREAD_LIB)	\
  $(XML2_LIB)		\
  $(GLIB2_LIB)		\
  $(HAIL_LIBS)

# leg is a lexer/parser-generator
# http://piumarta.com/software/peg/peg-0.1.4.tar.gz
query-orig.c: query.leg
	leg < $(srcdir)/query.leg > $@-t && mv $@-t $@

# Apply this patch to fix NULL-deref bugs in the generated query-orig.c:
query.c: query-orig.c query.c.diff
	patch --fuzz=0 query-orig.c $(srcdir)/query.c.diff --output=$@-t
	mv $@-t $@

BUILT_SOURCES = query.c
CLEANFILES = query-orig.c
MOSTLYCLEANFILES = query.c query-orig.c-t
MAINTAINERCLEANFILES = query.c query-orig.c
EXTRA_DIST += query.c.diff
