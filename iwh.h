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

/*
 * Front-end modes and global usage
 *
 * The front end might be in one of three modes: FS, repod, or S3.  FS mode
 * is distinguished from the other two by having proxy_host=NULL.  (In fact
 * what the "-f" flag does is set cfg_file=NULL, which suppresses parsing of
 * the config file; it's the parser that sets proxy_host to some other value.)
 * If proxy_host!=NULL then proxy_port and s3mode are also valid.  If s3mode
 * in turn is non-zero then proxy_key and proxy_secret are also valid.  I've
 * marked the relevant globals with the modes where they're valid.
 *
 * NONE OF THIS affects the back ends used for replication.  There can be
 * multiple such back ends, each individually repod or S3 mode with their
 * own keys/secrets.
 */

GLOBAL(int,		verbose,	0);
GLOBAL(const char *,	proxy_host,	NULL);		/* repod/S3 */
GLOBAL(unsigned short,	proxy_port,	MY_PORT+1);	/* repod/S3 */
GLOBAL(const char *,	proxy_key,	"foo");		/* S3 only */
GLOBAL(const char *,	proxy_secret,	"bar");		/* S3 only */
GLOBAL(const char *,	master_host,	NULL);
GLOBAL(unsigned short,	master_port,	MY_PORT);
GLOBAL(unsigned int,	s3mode,		0);		/* repod/S3 */
GLOBAL(const char *,	local_path,	"/tmp");	/* FS */
GLOBAL(const char *,	db_host,	"localhost");
GLOBAL(unsigned short,	db_port,	0);
GLOBAL(const char *,    me,             "here");

#define DPRINTF(fmt,args...) do {	\
	if (verbose) {			\
		printf(fmt,##args);	\
	}				\
} while (0)

#ifndef __attribute__
# if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 8)
#  define __attribute__(x) /* empty */
# endif
#endif

#ifndef ATTRIBUTE_UNUSED
# define ATTRIBUTE_UNUSED __attribute__ ((__unused__))
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
