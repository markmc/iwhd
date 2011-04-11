# Customize maint.mk                           -*- makefile -*-
# Copyright (C) 2009-2011 Free Software Foundation, Inc.

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

# Used in maint.mk's web-manual rule
manual_title = GNU Grep: Print lines matching a pattern

# Fixing these can wait.
skip_low_priority =			\
  sc_texinfo_acronym			\
  sc_prohibit_tab_based_indentation	\
  sc_prohibit_strcmp			\
  sc_error_message_uppercase		\
  sc_cast_of_argument_to_free		\
  sc_file_system

# Tests not to run as part of "make distcheck".
local-checks-to-skip =			\
  sc_program_name			\
  sc_space_tab				\
  sc_useless_cpp_parens			\
  $(skip_low_priority)

# Tools used to bootstrap this package, used for "announcement".
bootstrap-tools = autoconf,automake,gnulib

# Now that we have better tests, make this the default.
export VERBOSE = yes

old_NEWS_hash = e9ec1d38f8c5686545a3e1ed3ce34add

sc_prohibit_echo_minus_en:
	@prohibit='\<echo -[en]'					\
	halt='do not use echo ''-e or echo ''-n; use printf instead'	\
	  $(_sc_search_regexp)

# Indent only with spaces.
sc_prohibit_tab_based_indentation:
	@prohibit='^ *	'						\
	halt='TAB in indentation; use only spaces'			\
	  $(_sc_search_regexp)

# Don't use "indent-tabs-mode: nil" anymore.  No longer needed.
sc_prohibit_emacs__indent_tabs_mode__setting:
	@prohibit='^( *[*#] *)?indent-tabs-mode:'			\
	halt='use of emacs indent-tabs-mode: setting'			\
	  $(_sc_search_regexp)

odt = ^doc/image_repo\.odt$
exclude_file_name_regexp--sc_trailing_blank = $(odt)
exclude_file_name_regexp--sc_prohibit_empty_lines_at_EOF = $(odt)
exclude_file_name_regexp--sc_prohibit_test_double_equal = ^t/parse-test$$
exclude_file_name_regexp--sc_bindtextdomain = ^dc-rhev-image\.c$$

update-copyright-env = \
  UPDATE_COPYRIGHT_USE_INTERVALS=1 \
  UPDATE_COPYRIGHT_MAX_LINE_LENGTH=79

announcement_mail_headers_ =                                            \
To: iwhd-devel@lists.fedorahosted.org					\
Cc: aeolus-devel@lists.fedorahosted.org					\
Mail-Followup-To: iwhd-devel@lists.fedorahosted.org
