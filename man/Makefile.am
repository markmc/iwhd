# Automakefile for GNU diffutils man pages

# Copyright (C) 2002, 2009-2011 Free Software Foundation, Inc.

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

dist_man8_MANS = iwhd.8
MAINTAINERCLEANFILES = $(dist_man8_MANS)

# Depend on configure.ac to get version number changes.
iwhd.8: $(top_srcdir)/configure.ac $(top_srcdir)/rest.c
	$(AM_V_GEN) \
	  (echo '[NAME]' && sed 's@/\* *@@; s/-/\\-/; q' $(top_srcdir)/rest.c)|\
	  $(HELP2MAN) --no-info -i - -S '$(PACKAGE) $(VERSION)' ../iwhd | \
	  sed 's/^\.B info .*/.B info FIXME/' > $@-t && mv $@-t $@
