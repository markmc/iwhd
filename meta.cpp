#include <errno.h>
#include <stdio.h>
#include <sys/time.h>
#include <iostream>
#include "repo.h"
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

	char *	DidPut		(char * bucket, char * key, char * loc,
				 size_t size);
	void	GotCopy		(char * bucket, char * key, char * loc);
	char *	HasCopy		(char * bucket, char * key, char * loc);
	int	SetValue	(char * bucket, char * key, char * mkey,
				 char * mvalue);
	int	GetValue	(char * bucket, char * key, char * mkey,
				 char ** mvalue);
	RepoQuery * NewQuery	(char * bucket, char * key, char * expr);
	auto_ptr<DBClientCursor> GetCursor (Query &q);
	void	Delete		(char * bucket, char * key);
	size_t	GetSize		(char * bucket, char * key);
	int	Check		(char * bucket, char * key, char * depot);
};

class RepoQuery {
	RepoMeta &		parent;
	DBClientCursor *	curs;
	value_t *		expr;
public:
		RepoQuery	(char *, char *, char *, RepoMeta &);
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
RepoMeta::DidPut (char * bucket, char * key, char * loc, size_t size)
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
meta_did_put (char * bucket, char * key, char * loc, size_t size)
{
	cout << "meta_did_put(" << bucket << "," << key << "," << loc << ")"
	     << endl;
	return it->DidPut(bucket,key,loc,size);
}

void
RepoMeta::GotCopy (char * bucket, char * key, char * loc)
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
meta_got_copy (char * bucket, char * key, char * loc)
{
	it->GotCopy(bucket,key,loc);
}

char *
RepoMeta::HasCopy (char * bucket, char * key, char * loc)
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
meta_has_copy (char * bucket, char * key, char * loc)
{
	return it->HasCopy(bucket,key,loc);
}

int
RepoMeta::SetValue (char * bucket, char * key, char * mkey, char * mvalue)
{
	Query	q	= QUERY("bucket"<<bucket<<"key"<<key);

	client.update(MAIN_TBL,q,BSON("$set"<<BSON(mkey<<mvalue)),1);
	// TBD: check for and propagate errors.
	return 0;
}

extern "C" int
meta_set_value (char * bucket, char * key, char * mkey, char * mvalue)
{
	return it->SetValue(bucket,key,mkey,mvalue);
}

int
RepoMeta::GetValue (char * bucket, char * key, char * mkey, char ** mvalue)
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
meta_get_value (char * bucket, char * key, char * mkey, char ** mvalue)
{
	return it->GetValue(bucket,key,mkey,mvalue);
}

RepoQuery::RepoQuery (char * bucket, char * key, char *qstr, RepoMeta &p)
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
	delete (RepoQuery *)qobj;
}

extern "C" char *
query_getter (void *ctx, char *id)
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
RepoMeta::NewQuery (char * bucket, char * key, char *expr)
{
	return new RepoQuery(bucket,key,expr,*this);
}

extern "C" void *
meta_query_new (char * bucket, char * key, char *expr)
{
	if ((bucket && key) || (!bucket && !key)) {
		return NULL;
	}
	return it->NewQuery(bucket,key,expr);
}

extern "C" int
meta_query_next (void * qobj, char ** bucket, char ** key)
{
	RepoQuery *	rq	= (RepoQuery *)qobj;

	if (!rq->Next()) {
		return 0;
	}

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
RepoMeta::Delete (char * bucket, char * key)
{
	Query	q	= QUERY("bucket"<<bucket<<"key"<<key);

	client.remove(MAIN_TBL,q);
}

extern "C"
void
meta_delete (char * bucket, char * key)
{
	it->Delete(bucket,key);
}

size_t
RepoMeta::GetSize (char * bucket, char * key)
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
meta_get_size (char * bucket, char * key)
{
	return it->GetSize(bucket,key);
}

