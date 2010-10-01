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

#include <config.h>

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/time.h>
#include <iostream>
#include "iwh.h"
#include "meta.h"
#include "query.h"

using namespace std;

/* Mongo (rather antisocially) tries to define this itself. */
#if defined(VERSION)
#undef VERSION
#endif

#include <mongo/client/dbclient.h>
using namespace mongo;

/* TBD: parameterize */
#define MAIN_TBL "repo.main"

/*
 * Since the client isn't inherently MT-safe, we serialize access to it
 * ourselves.  Fortunately, none of our metadata operations should be very
 * long-lived; if they are it probably means our connection is FUBAR and other
 * threads will be affected anyway.
 */

#define SHOW_CONTENTION

pthread_mutex_t		client_lock	= PTHREAD_MUTEX_INITIALIZER;
#if defined(SHOW_CONTENTION)
#define CLIENT_LOCK do {					\
	if (pthread_mutex_trylock(&client_lock) != 0) {		\
		cout << "contention in " << __func__ << endl;	\
		pthread_mutex_lock(&client_lock);		\
	}							\
} while (0)
#else
#define CLIENT_LOCK	pthread_mutex_lock(&client_lock)
#endif
#define CLIENT_UNLOCK	pthread_mutex_unlock(&client_lock)

void
dbl_to_str (double *foo, char *optr)
{
	int i;
	unsigned char *iptr = (unsigned char *)foo;

	for (i = 0; i < sizeof(*foo); ++i) {
		optr += sprintf(optr,"%02x",*(iptr++));
	}
}

class RepoMeta;
class RepoQuery;

class RepoMeta {

public:
		RepoMeta	();
		~RepoMeta	();

	DBClientConnection	client;

	char *	DidPut		(const char *bucket, const char *key,
				 const char *loc, size_t size);
	void	GotCopy		(const char *bucket, const char *key,
				 const char *loc);
	char *	HasCopy		(const char *bucket, const char *key,
				 const char *loc);
	int	SetValue	(const char *bucket, const char *key,
				 const char *mkey, const char * mvalue);
	int	GetValue	(const char *bucket, const char *key,
				 const char *mkey, char ** mvalue);
	RepoQuery * NewQuery	(const char *bucket, const char *key,
				 const char * expr);
	auto_ptr<DBClientCursor> GetCursor (Query &q);
	void	Delete		(const char *bucket, const char *key);
	size_t	GetSize		(const char *bucket, const char *key);
	int	Check		(const char *bucket, const char *key,
				 const char *depot);
};

class RepoQuery {
	RepoMeta &		parent;
	DBClientCursor *	curs;
	value_t *		expr;
public:
		RepoQuery	(const char *, const char *, const char *,
				 RepoMeta &);
		~RepoQuery	();
	bool	Next		(void);
	char	*bucket;
	char	*key;
	getter_t getter;
};

RepoMeta *it;

RepoMeta::RepoMeta ()
{
	char	addr[128];

	sprintf(addr,"%s:%u",db_host,db_port);
	client.connect(addr);
}

extern "C" void
meta_init (void)
{
	it = new RepoMeta();
}

RepoMeta::~RepoMeta ()
{
}

extern "C" void
meta_fini (void)
{
	delete it;
}

auto_ptr<DBClientCursor>
RepoMeta::GetCursor (Query &q)
{
	auto_ptr<DBClientCursor> curs;

	curs = client.query(MAIN_TBL,q);
	if (!curs.get()) {
		cout << "reconnecting" << endl;
		try {
			client.connect("localhost");
		}
		catch (ConnectException &ce) {
			cout << "server down" << endl;
			throw;
		}
		curs = client.query(MAIN_TBL,q);
	}

	return curs;
}

char *
RepoMeta::DidPut (const char *bucket, const char *key, const char *loc,
		  size_t size)
{
	BSONObjBuilder			bb;
	struct timeval			now_tv;
	double				now;
	auto_ptr<DBClientCursor>	curs;
	Query				q;
	char				now_str[sizeof(now)*2+1];

	gettimeofday(&now_tv,NULL);
	now = (double)now_tv.tv_sec + (double)now_tv.tv_usec / 1000000.0;
	dbl_to_str(&now,now_str);
	cout << "now_str = " << now_str << endl;

	q = QUERY("bucket"<<bucket<<"key"<<key);
	curs = GetCursor(q);
	if (curs->more()) {
		/* Nice functionality, but what an ugly syntax! */
		client.update(MAIN_TBL,q,BSON(
			"$set"<<BSON("loc"<<BSON_ARRAY(loc))
		<<	"$set"<<BSON("date"<<now)
		<<	"$set"<<BSON("etag"<<now_str)
		<<	"$set"<<BSON("size"<<(long long)size)));
#if 0
		client.update(MAIN_TBL,q,
			BSON("$set"<<BSON("loc"<<BSON_ARRAY(loc))));
		client.update(MAIN_TBL,q,
			BSON("$set"<<BSON("date"<<now)));
		client.update(MAIN_TBL,q,
			BSON("$set"<<BSON("etag"<<now_str)));
		client.update(MAIN_TBL,q,
			BSON("$set"<<BSON("size"<<(long long)size)));
#endif
	}
	else {
		bb << "bucket" << bucket << "key" << key
		   << "loc" << BSON_ARRAY(loc) << "date" << now
		   << "etag" << now_str << "size" << (long long)size;
		client.insert(MAIN_TBL,bb.obj());
	}

	return strdup(now_str);
}

extern "C" char *
meta_did_put (const char *bucket, const char *key, const char *loc, size_t size)
{
	char	*rc;

	cout << "meta_did_put(" << bucket << "," << key << "," << loc << ")"
	     << endl;

	CLIENT_LOCK;
	rc = it->DidPut(bucket,key,loc,size);
	CLIENT_UNLOCK;

	return rc;
}

void
RepoMeta::GotCopy (const char *bucket, const char *key, const char *loc)
{
	BSONObjBuilder			bb;
	auto_ptr<DBClientCursor>	curs;
	Query				q;

	q = QUERY("bucket"<<bucket<<"key"<<key);
	curs = GetCursor(q);
	if (curs->more()) {
		/* Nice functionality, but what an ugly syntax! */
		client.update(MAIN_TBL,q,BSON("$addToSet"<<BSON("loc"<<loc)));
	}
	else {
		cerr << bucket << ":" << key << " not found in GotCopy!" << endl;
	}
}

extern "C" void
meta_got_copy (const char *bucket, const char *key, const char *loc)
{
	CLIENT_LOCK;
	it->GotCopy(bucket,key,loc);
	CLIENT_UNLOCK;
}

char *
RepoMeta::HasCopy (const char *bucket, const char *key, const char *loc)
{
	BSONObjBuilder			bb;
	auto_ptr<DBClientCursor>	curs;
	Query				q;
	const char			*value;

	q = QUERY("bucket"<<bucket<<"key"<<key<<"loc"<<loc);
	curs = GetCursor(q);
	if (!curs->more()) {
		cout << bucket << "/" << key << " not found at " << loc << endl;
		return NULL;
	}

	value = curs->next().getStringField("etag");
	if (!value || !*value) {
		cout << bucket << "/" << key << " no etag at " << loc << endl;
		return NULL;
	}

	cout << bucket << "/" << key << " etag = " << value << endl;
	return strdup(value);
}

extern "C" char *
meta_has_copy (const char *bucket, const char *key, const char *loc)
{
	char	*rc;

	CLIENT_LOCK;
	rc = it->HasCopy(bucket,key,loc);
	CLIENT_UNLOCK;

	return rc;
}

int
RepoMeta::SetValue (const char *bucket, const char *key, const char *mkey,
		    const char * mvalue)
{
	Query	q	= QUERY("bucket"<<bucket<<"key"<<key);

	client.update(MAIN_TBL,q,BSON("$set"<<BSON(mkey<<mvalue)),1);
	// TBD: check for and propagate errors.
	return 0;
}

extern "C" int
meta_set_value (const char *bucket, const char *key, const char *mkey,
		const char * mvalue)
{
	int	rc;

	CLIENT_LOCK;
	rc = it->SetValue(bucket,key,mkey,mvalue);
	CLIENT_UNLOCK;

	return rc;
}

int
RepoMeta::GetValue (const char *bucket, const char *key, const char *mkey,
		    char ** mvalue)
{
	auto_ptr<DBClientCursor>	curs;
	Query				q;
	BSONObj				bo;
	const char *			data;

	q = QUERY("bucket"<<bucket<<"key"<<key);
	curs = GetCursor(q);

	if (!curs->more()) {
		return ENXIO;
	}

	bo = curs->next();
	data = bo.getStringField(mkey);
	if (!data || !*data) {
		return ENXIO;
	}

	*mvalue = strdup(data);
	return 0;
}

extern "C" int
meta_get_value (const char *bucket, const char *key, const char *mkey,
		char ** mvalue)
{
	int	rc;

	CLIENT_LOCK;
	rc = it->GetValue(bucket,key,mkey,mvalue);
	CLIENT_UNLOCK;

	return rc;
}

RepoQuery::RepoQuery (const char *bucket, const char *key, const char *qstr,
		      RepoMeta &p)
	: parent(p)
{
	Query				q;
	auto_ptr<DBClientCursor>	tmp;

	if (bucket) {
		cout << "bucket is " << bucket << " and we don't care" << endl;
		q = QUERY("bucket"<<bucket);
	}
	else if (key) {
		cout << "key is " << key << " and we don't care" << endl;
		q = QUERY("key"<<key);
	}
	else {
		abort();
	}

	/*
	 * TBD: we should really convert our query into one of Mongo's,
	 * and let them do all the work.  Handling the general case
	 * would be pretty messy, but we could handle specific cases
	 * pretty easily.  For example, a very high percentage of
	 * queries are likely to be a single field/value comparison.
	 * For now just punt, but revisit later.
	 */

	if (qstr) {
		expr = parse(qstr);
		if (expr) {
			print_value(expr);
		}
		else {
			cout << "could not parse " << qstr << endl;
		}
	}
	else {
		expr = NULL;
	}

	curs = parent.GetCursor(q).release();
	bucket = NULL;
	key = NULL;
}

RepoQuery::~RepoQuery ()
{
	cout << "in " << __func__ << endl;
	if (expr) {
		free_value(expr);
	}

	delete curs;
}

extern "C" void
meta_query_stop (void * qobj)
{
	CLIENT_LOCK;
	delete (RepoQuery *)qobj;
	CLIENT_UNLOCK;
}

extern "C" char *
query_getter (void *ctx, const char *id)
{
	BSONObj *cur_bo = (BSONObj *)ctx;

	return (char *)cur_bo->getStringField(id);
}

bool
RepoQuery::Next (void)
{
	BSONObj		bo;

	while (curs->more()) {
		bo = curs->next();
		if (expr) {
			getter.func = query_getter;
			getter.ctx = (void *)&bo;
			if (eval(expr,&getter,NULL) <= 0) {
				continue;
			}
		}
		bucket = (char *)bo.getStringField("bucket");
		key = (char *)bo.getStringField("key");
		return true;
	}

	return false;
}

RepoQuery *
RepoMeta::NewQuery (const char *bucket, const char *key, const char *expr)
{
	return new RepoQuery(bucket,key,expr,*this);
}

extern "C" void *
meta_query_new (const char *bucket, const char *key, const char *expr)
{
	void	*rc;

	if ((bucket && key) || (!bucket && !key)) {
		return NULL;
	}

	CLIENT_LOCK;
	rc = it->NewQuery(bucket,key,expr);
	CLIENT_UNLOCK;

	return rc;
}

extern "C" int
meta_query_next (void * qobj, char ** bucket, char ** key)
{
	RepoQuery *	rq	= (RepoQuery *)qobj;

	CLIENT_LOCK;
	if (!rq->Next()) {
		CLIENT_UNLOCK;
		return 0;
	}
	CLIENT_UNLOCK;

	*bucket = rq->bucket;
	*key = rq->key;
	return 1;
}

#if 0
char *
RepoMeta::BucketList (void)
{
	/*
	 * TBD: make this return values instead of producing output.
	 * This is just a code fragment showing how to get a list of buckets,
	 * in case I forget.
	 */
	BSONObj				repl;

	BSONObj dist = BSON("distinct"<<"main"<<"key"<<"bucket");
	if (client.runCommand("repo",dist,repl)) {
		cout << repl.toString() << endl;
		BSONObj elem = repl.getField("values").embeddedObject();
		for (int i = 0; i < elem.nFields(); ++i) {
			cout << elem[i].str() << endl;
		}
	}
}
#endif

void
RepoMeta::Delete (const char *bucket, const char *key)
{
	Query	q	= QUERY("bucket"<<bucket<<"key"<<key);

	client.remove(MAIN_TBL,q);
}

extern "C"
void
meta_delete (const char *bucket, const char *key)
{
	CLIENT_LOCK;
	it->Delete(bucket,key);
	CLIENT_UNLOCK;
}

size_t
RepoMeta::GetSize (const char *bucket, const char *key)
{
	auto_ptr<DBClientCursor>	curs;
	Query				q;
	BSONObj				bo;
	const char *			data;

	q = QUERY("bucket"<<bucket<<"key"<<key);
	curs = GetCursor(q);

	if (!curs->more()) {
		return 0;
	}

	bo = curs->next();
	return bo.getField("size").numberLong();
}

extern "C"
size_t
meta_get_size (const char *bucket, const char *key)
{
	size_t	rc;

	CLIENT_LOCK;
	rc = it->GetSize(bucket,key);
	CLIENT_UNLOCK;

	return rc;
}
