#define MY_PORT 9090

#if defined(GLOBALS_IMPL)
#define GLOBAL(type,name,value)	type name = value;
#else
#define GLOBAL(type,name,value)	extern type name;
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

GLOBAL(int,		verbose,	0)
GLOBAL(char *,		cfg_file,	"repo.json")
GLOBAL(const char *,	proxy_host,	NULL)		/* always */
GLOBAL(unsigned short,	proxy_port,	MY_PORT+1)	/* repod/S3 */
GLOBAL(const char *,	proxy_key,	"foo")		/* S3 only */
GLOBAL(const char *,	proxy_secret,	"bar")		/* S3 only */
GLOBAL(unsigned int,	s3mode,		0)		/* repod/S3 */
GLOBAL(const char *,	db_host,	"localhost")
GLOBAL(unsigned short,	db_port,	27017)
GLOBAL(char *,          me,             "here")

#define I2P(x)	((void *)(long)(x))
#define P2I(x)	((int)(long)(x))

#define DPRINTF(fmt,args...) { \
	if (verbose)			{	\
		printf(fmt,##args);		\
	}					\
}

#ifndef __attribute__
# if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 8)
#  define __attribute__(x) /* empty */
# endif
#endif

#ifndef ATTRIBUTE_UNUSED
# define ATTRIBUTE_UNUSED __attribute__ ((__unused__))
#endif
