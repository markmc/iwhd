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

#ifndef _LOGGING_H
#define _LOGGING_H

typedef enum {
  LOG_DEBUG = 0,
  LOG_INFO,
  LOG_WARN,
  LOG_ERR,
} log_level_t;

void log_msg(log_level_t level, const char *fmt, ...);
void log_init(log_level_t level, const char *path);
void log_reset(void);

#define error(status, err, fmt, args...) log_msg(LOG_ERR, fmt, ##args)
#define DPRINTF(fmt, args...) log_msg(LOG_DEBUG, fmt,  ##args)

#endif
