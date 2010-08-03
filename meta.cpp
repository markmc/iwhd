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

/* TBD: ick!  Need to make the parser/query stuff reentrant. */
static BSONObj cur_bo;

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
	RepoQuery * NewQuery	(char * expr);
	auto_ptr<DBClientCursor> GetCursor (Query &q);
	void	Delete		(char * bucket, char * key);
	size_t	GetSize		(char * bucket, char * key);

private:
	void	BucketList	(void);	/* just sample code, don't use */
};

class RepoQuery {
	RepoMeta &		parent;
	DBClientCursor *	curs;
	value_t *		expr;
public:
		RepoQuery	(char *, RepoMeta &);
		~RepoQuery	();
	bool	Next		(void);
	char	*bucket;
	char	*key;
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

	/* TBD: disambiguate master/slave cases a better way */
	extern char * master_host;

	gettimeofday(&now_tv,NULL);
	now = (double)now_tv.tv_sec + (double)now_tv.tv_usec / 1000000.0;
	dbl_to_str(&now,now_str);
	cout << "now_str = " << now_str << endl;

	q = QUERY("bucket"<<bucket<<"key"<<key);
	curs = GetCursor(q);
	if (curs->more()) {
		/* Nice functionality, but what an ugly syntax! */
		if (master_host) {
			client.update(MAIN_TBL,q,
				BSON("$addToSet"<<BSON("loc"<<loc)));
		}
		else {
			client.update(MAIN_TBL,q,
				BSON("$set"<<BSON("loc"<<BSON_ARRAY(loc))));
		}
		client.update(MAIN_TBL,q,BSON("$set"<<BSON("date"<<now)));
		client.update(MAIN_TBL,q,BSON("$set"<<BSON("etag"<<now_str)));
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
		return NULL;
	}

	value = curs->next().getStringField("etag");
	if (!value || !*value) {
		return NULL;
	}
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

RepoQuery::RepoQuery (char *qstr, RepoMeta &p) : parent(p)
{
	Query				q;
	auto_ptr<DBClientCursor>	tmp;

	if (*qstr == '/') {
		expr = NULL;
		q = QUERY("bucket"<<qstr+1);
	}
	else {
		expr = parse(qstr);
		if (expr) {
			print_value(expr);
		}
		/*
		 * TBD: we should really convert our query into one of Mongo's,
		 * and let them do all the work.  Handling the general case
		 * would be pretty messy, but we could handle specific cases
		 * pretty easily.  For example, a very high percentage of
		 * queries are likely to be a single field/value comparison.
		 * For now just punt, but revisit later.
		 */
		q = Query();
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

	if (bucket) {
		free(bucket);
	}
	if (key) {
		free(key);
	}
}

extern "C" void
meta_query_stop (void * qobj)
{
	delete (RepoQuery *)qobj;
}

extern "C" char *
query_getter (char *id)
{
	return (char *)cur_bo.getStringField(id);
}

bool
RepoQuery::Next (void)
{
	BSONObj		bo;

	while (curs->more()) {
		bo = curs->next();
		if (expr) {
			cur_bo = bo;
			if (eval(expr,&query_getter,NULL) <= 0) {
				continue;
			}
		}
		if (bucket) { free(bucket); }
		bucket = strdup(bo.getStringField("bucket"));
		if (key) { free(key); }
		key = strdup(bo.getStringField("key"));
		return true;
	}

	curs = NULL;
	return false;
}

RepoQuery *
RepoMeta::NewQuery (char *expr)
{
	return new RepoQuery(expr,*this);
}

extern "C" void *
meta_query_new (char *expr)
{
	return it->NewQuery(expr);
}

extern "C" int
meta_query_next (void * qobj, char ** bucket, char ** key)
{
	RepoQuery *	rq	= (RepoQuery *)qobj;

	if (!rq->Next()) {
		delete rq;
		return 0;
	}

	*bucket = rq->bucket;
	*key = rq->key;
	return 1;
}

void
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
