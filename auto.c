#include <config.h>

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <stdarg.h>		/* for microhttpd.h (bug in there) */
#include <stdint.h>		/* for microhttpd.h (bug in there) */
#include <jansson.h>

#include "setup.h"
#include "iwh.h"

static char auto_arg_port[10];

static char *auto_arg_mongod[] = {
	"mongod",
	"--port", auto_arg_port,
	"--dbpath", AUTO_DIR_DB,
	/* "--fork", */	/* chdirs god knows where, we cannot use this. */
	/* "--logpath", AUTO_MONGOD_LOG, */	/* required by --fork */
	/* "--logappend", */
	"--pidfilepath", "mongo.pid",
	NULL
};

/* The --quiet option in mongod is useless, so redirect instead. */
static char *auto_arg_mongod_quiet[] = {
	"mongod",
	"--port", auto_arg_port,
	"--dbpath", AUTO_DIR_DB,
	"--logpath", AUTO_MONGOD_LOG,
	"--pidfilepath", "mongo.pid",
	NULL
};

static int auto_pid_mongod;

static int
auto_mkdir (const char *name)
{
	struct stat	statb;

	if (mkdir(name, 0777) < 0) {
		if (errno == EEXIST) {
			if (stat(name, &statb) < 0) {
				error (0, errno, "stat %s failed", name);
				return -1;
			}
			if (!S_ISDIR(statb.st_mode)) {
				error (0, 0, "path %s is not a directory",name);
				return -1;
			}
			return 0;
		}
		error(0, errno, "Cannot create %s", name);
		return -1;
	}
	return 0;
}

static int
auto_prepare_area (void)
{

	if (auto_mkdir(AUTO_DIR_FS) < 0) {
		return -1;
	}
	if (auto_mkdir(AUTO_DIR_DB) < 0) {
		return -1;
	}
	return 0;
}

static void
auto_kill_mongod (int sig)
{
	if (auto_pid_mongod) {
		kill(auto_pid_mongod, sig);
	}
}

static int
auto_spawn (const char *prog, char *argv[])
{
	struct stat	statb;
	pid_t		pid;

	/*
	 * The stat check is purely so that common errors, such as ENOENT
	 * if the program is not available, were printed before the fork.
	 * This serves no security purpose but only makes stderr more tidy.
	 */
	if (stat(prog, &statb) < 0) {
		error (0, errno, "stat %s failed", prog);
		return -1;
	}
	if (!S_ISREG(statb.st_mode)) {
		error (0, 0, "path %s is not a regular file", prog);
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		error (0, errno, "fork failed");
		return -1;
	}

	if (pid == 0) {
		execvp(prog, argv);
		error (EXIT_FAILURE, errno, "failed to run command %s", prog);
	}

	/*
	 * This is where you'd normally run waitpid for your daemon, so that
	 * argument check failures were caught at least. In case of mongod,
	 * daemonizing it is a whole can of worms, so we do not. On the
	 * upside, it stays on our session (and process group) and dies
	 * cleanly on keyboard interrupt.
	 */

	return pid;
}

/*
 * The server_node and node_resolve are taken verbatim from wait-for-listen.
 * Is this time to factor?
 */
#define ADDRSIZE 40

struct server_node {
	unsigned		alen;
	union {
		struct sockaddr addr;
		unsigned char x[ADDRSIZE];
	} a;
};

static int
node_resolve(struct server_node *sn,
	     const char *hostname, const char *portstr)
{
	struct addrinfo hints;
	struct addrinfo *res, *res0;
	int rc;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	rc = getaddrinfo(hostname, portstr, &hints, &res0);
	if (rc) {
		error(0, 0, "getaddrinfo(%s:%s) failed: %s",
		       hostname, portstr, gai_strerror(rc));
		return -1;
	}

	for (res = res0; res; res = res->ai_next) {
		if (res->ai_family != AF_INET && res->ai_family != AF_INET6)
			continue;

		if (res->ai_addrlen > ADDRSIZE)		/* should not happen */
			continue;

		memcpy(&sn->a.addr, res->ai_addr, res->ai_addrlen);
		sn->alen = res->ai_addrlen;

		freeaddrinfo(res0);
		return 0;
	}

	freeaddrinfo(res0);
	return -1;
}

static int
auto_test_mongod(void)
{
	struct server_node snode, *sn = &snode;
	int sfd;
	int rc;

	memset(sn, 0, sizeof(struct server_node));
	if (node_resolve(sn, AUTO_HOST, auto_arg_port) != 0) {
		/*
		 * Most likely nothing else would work anyway. So abend.
		 */
		error(0, 0, "unable to resolve host %s port %s",
		      AUTO_HOST, auto_arg_port);
		return -1;
	}

	DPRINTF("trying to connect to mongod (host %s port %s) ...\n",
		AUTO_HOST, auto_arg_port);

	sfd = socket(sn->a.addr.sa_family, SOCK_STREAM, 0);
	if (sfd < 0) {
		error(0, errno, "socket");
		return -1;
	}

	rc = connect(sfd, &sn->a.addr, sn->alen);
	if (rc != 0) {
		DPRINTF("connect: %s\n", strerror(errno));
		close(sfd);
		return 1;
	}

	close(sfd);
	return 0;
}

static int
auto_wait_mongod(void)
{
	struct timespec ts;
	time_t start_time;
	int rc;

	start_time = time(NULL);
	for (;;) {
		rc = auto_test_mongod();
		if (rc == 0)
			break;
		if (time(NULL) >= start_time + 5) {
			error(0, 0, "failed to verify mongod using port %s",
			      auto_arg_port);
			return -1;
		}

		ts.tv_sec = 1;
		ts.tv_nsec = 0;
		nanosleep(&ts, NULL);
	}
	DPRINTF("mongod went up after %ld s\n", (long)time(NULL) - start_time);

	return 0;
}

static void
auto_action (int sig, siginfo_t *info, void *uctx)
{
	(void) info;
	(void) uctx;

	if (sig == SIGSEGV || sig == SIGILL || sig == SIGFPE || sig == SIGBUS) {
		auto_kill_mongod(SIGTERM);
	}
	else {
		auto_kill_mongod(info->si_signo);
	}
}

static int
auto_set_sig (void)
{
	struct sigaction actb;

	memset(&actb, 0, sizeof(struct sigaction));
	actb.sa_flags |= SA_SIGINFO;
	actb.sa_sigaction = auto_action;

	/* Not trapping SIGINT or SIGHUP since mongo is in our session. */
	if (sigaction(SIGTERM, &actb, NULL) ||
	    sigaction(SIGSEGV, &actb, NULL) ||
	    sigaction(SIGILL, &actb, NULL) ||
	    sigaction(SIGFPE, &actb, NULL) ||
	    sigaction(SIGBUS, &actb, NULL) ||
	    sigaction(SIGABRT, &actb, NULL)) {
		error(0, errno, "sigaction");
		return -1;
	}
	return 0;
}

static void
auto_stop (void)
{
	auto_kill_mongod(SIGTERM);
}

int
auto_start (int dbport)
{
	int rc;
	char **earg;
	int pid;

	snprintf(auto_arg_port, sizeof(auto_arg_port), "%u", dbport);

	if (auto_prepare_area() < 0)
		return -1;

	rc = auto_test_mongod();
	if (rc < 0)
		return -1;

	/*
	 * This is a trick. The auto_test_mongod() merely connects to a TCP
	 * port, and does not execute a NO-OP in Mongo. Therefore, it succeeds
	 * if a foreign application is listening on our private port.
	 * We abort because we do not want anyone listening there.
	 */
	if (rc == 0) {
		error (0, 0, "something is listening on port %s,"
		       " not auto-starting Mongo", auto_arg_port);
		return -1;
	}

	DPRINTF("auto-starting mongod\n");
	earg = verbose ? auto_arg_mongod : auto_arg_mongod_quiet;
	pid = auto_spawn(AUTO_BIN_MONGOD, earg);
	if (pid < 0)
		return -1;
	auto_pid_mongod = pid;
	if (auto_wait_mongod() < 0) {
		auto_kill_mongod(SIGTERM);
		return -1;
	}

	if (auto_set_sig() < 0) {
		auto_kill_mongod(SIGTERM);
		return -1;
	}
	if (atexit(auto_stop) != 0) {
		error (0, 0, "atexit failed for auto_stop");
		auto_kill_mongod(SIGTERM);
		return -1;
	}

	DPRINTF("mongod listens on port %u\n", dbport);
	return 0;
}
