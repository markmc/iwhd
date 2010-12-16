/* Copyright (C) 2010 Red Hat, Inc.

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

#define MY_PORT 9090

#if defined(GLOBALS_IMPL)
#define GLOBAL(type,name,value)	type name = value
#else
#define GLOBAL(type,name,value)	extern type name
#endif

GLOBAL(int,		verbose,	0);
GLOBAL(const char *,	master_host,	NULL);
GLOBAL(unsigned short,	master_port,	MY_PORT);
GLOBAL(const char *,	db_host,	"localhost");
GLOBAL(unsigned short,	db_port,	0);
GLOBAL(const char *,    me,             "here");

#define DPRINTF(fmt,args...) do {			\
	if (verbose) {					\
		printf("%d " fmt,getpid(),##args);	\
		fflush(stdout);				\
	}						\
} while (0)

#ifndef __attribute__
# if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 8)
#  define __attribute__(x) /* empty */
# endif
#endif

#ifndef ATTRIBUTE_UNUSED
# define ATTRIBUTE_UNUSED __attribute__ ((__unused__))
#endif

#ifndef ATTRIBUTE_NORETURN
# define ATTRIBUTE_NORETURN __attribute__ ((__noreturn__))
#endif

/*
 * Common parts of autostart
 *
 * Directories are relative so they are based off local_path.
 * Notice that we continue to use the underscore convention even though
 * buckets are inside the AUTO_DIR_FS and do not conflict. Visual help:
 * you can see what to delete right away.
 *
 * We want our own Mongo instance for autostart. Mongo does not have
 * a feature "listen on port 0 and tell us what you got" (like Hail),
 * so we define a port and hope it's not in use...
 */
#define AUTO_HOST	"localhost"
#define AUTO_DIR_FS	"_fs"
#define AUTO_DIR_DB	"_db"
#define AUTO_BIN_MONGOD	"/usr/bin/mongod"
#define AUTO_MONGOD_LOG	"_mongod.log"
#define AUTO_MONGOD_PORT 27018

int	 auto_start		(int dbport);
