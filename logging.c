/* Copyright (C) 2010-2011 Red Hat, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include <config.h>

#include "logging.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "iwh.h"

static log_level_t loglevel = LOG_WARN;
static const char *logfile;
static FILE *logstream;

static char *strip_newline(char *s)
{
	int len = strlen(s);
	if (len && s[len-1] == '\n') {
		s[len-1] = '\0';
	}
	return s;
}

static char *tstamp(char *buf) {
	time_t now;
	time(&now);
	return strip_newline(ctime_r(&now, buf));
}

static void log_str(const char *str)
{
	char tbuf[30];
	FILE *stream = logstream ? logstream : stderr;
	fprintf(stream, "%s iwhd[%d]: %s\n", tstamp(tbuf), getpid(), str);
	fflush(stream);
}

void log_msg(log_level_t level, const char *fmt, ...)
{
	va_list args;
	char buf[1024];
	int size;

	if (level < loglevel)
		return;

	va_start(args, fmt);
	size = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (size < 0) {
		error(0, 0, _("Error formatting log message"));
		return;
	}

	log_str(strip_newline(buf));

	if (size >= sizeof(buf)) {
		error(0, 0, _("The previous log message was truncated"));
	}
}

void log_init(log_level_t level, const char *path)
{
	loglevel = level;

	if (!path)
		return;

	logstream = fopen(path, "a+");
	if (!logstream) {
		error(_("Failed to open log file %s: %s\n"),
		      path, strerror(errno));
		return;
	}

	logfile = path;
}

void log_reset()
{
	if (!logfile)
		return;

	logstream = freopen(logfile, "a+", logstream);
	if (!logstream) {
		error(_("Failed to reopen log file %s: %s\n"),
		      logfile, strerror(errno));
	}
}
