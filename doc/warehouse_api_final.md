Image Warehouse API
===================

Version 0.8
-----------

This is my attempt to document the current state of the REST API
to the image warehouse, in its proposed final state and (in an
appendix) in its current messy state. It does not cover authentication,
fully dynamic configuration, or lesser items such as

* reverse replication (pull from slave/downstream warehouse);

* direct copy;

* cache control;

* HTTP chunked encoding.



In general, data other than object bodies can be returned in either
XML or JSON format, defaulting to XML unless an "Accept" header
containing "/json" is present.

For examples, the convention in this document is for the first
line of an indented block to be the command you would issue, while
the remainder is the output you might expect.

API Root Operations
-------------------

The only operation for the API root is to fetch information about
other API components, including buckets and special endpoints
such as the provider list. In other words, the

		$ curl http://fserver-1:9090
		<api service="image_warehouse" version="1.0">
			<bucket_factory path="http://fserver-1:9090/_new"/>
			<provider_list path="http://fserver-1:9090/_providers"/>
			<bucket path="http://fserver-1:9090/junk2"/>
			<bucket path="http://fserver-1:9090/data"/>
		</api>

The "service" and "version" attributes identify this version
of the warehouse API. Special API endpoints are distinguished
by a leading underscore, as with the "bucket_factory" endpoint
for creating new buckets and the "providers" endpoint for manipulating
cloud-provider information. The remainder are actual buckets.

Provider Operations
-------------------

It is possible to list providers, and to change login credentials
for those providers. Listing is very simple:

		$ curl http://fserver-1:9090/_providers
		<providers>
			<provider name="my tabled">
				<type>s3</type>
				<port>80</port>
				<username>foo</username>
				<password>bar</password>
			</provider>
			<provider name="backup">
				<type>http</type>
				<host>localhost</host>
				<port>9091</port>
			</provider>
		</providers>

This shows two providers, named "my tabled" (our primary/local
store) and "backup" (a secondary/remote store). The types can
be:

* http: our own API as described in this document

* s3: S3 - includes Amazon S3, tabled, Walrus, ParkPlace, Google
  Storage

* cf: CloudFiles or OpenStack Storage ("swift")



For the time being, "s3" is the only fully functional type for
a primary store, while any type can be used for a secondary store.
Slave stores can also be started with the "-f" flag which uses
a directory as a primary store but does no metadata/replication
operations. Eventually, all of these options - including a directory
on a local or distributed filesystem - will be supported as either
primary or secondary stores.

The only modifying operation for providers is an update of the
username and password (must be both at once). For example:

		$ curl -d provider="my tabled" -d username=yyy -d password=zzz \
http://fserver-1:9090/_providers

Bucket Operations
-----------------

Buckets can be created, listed, and deleted. The create command
is like this (using POST).

		$ curl -d name=my_bucket http://fserver-1:9090/_new

Deletion requires that the bucket be empty, but is similarly
simple.

		$ curl -X DELETE http://fserver-1:9090/my_bucket

Here's a listing of a bucket's contents, using JSON just for variety.

		$ curl -H "Accept: */json" http://fserver-1:9090/my_bucket
		[
			{
				"type": "query",
				"path": "http://fserver-1:9090/my_bucket/_query"
			{
				"type": "object",
				"name": "file1",
				"path": "http://fserver-1:9090/my_bucket/file1"
			},
			{
				"type": "object",
				"name": "file2",
				"path": "http://fserver-1:9090/my_bucket/file1"
			}
		]

The query object is used to do complex queries, which will be described
later. The remainder are regular objects.

Object and Attribute Operations
-------------------------------

Objects are represented as small directory trees, with several
elements as shown here:

		$ curl http://fserver-1:9090/my_bucket/file1
		<object>
			<object_body path="http://fserver-1:9090/my_bucket/file1/body"/>
			<object_attr_list path="http://fserver-1:9090/my_bucket/file1/attrs"/>
			<object_attr name="xyz" path="http://fserver-1:9090/my_bucket/file1/attr_xyz"/>
		</object>

The object body can be stored and retrieved using PUT and GET respectively,
and can have any HTTP/MIME type. The attribute-list element
can be used to fetch or set multiple attributes - including values
- at once. To fetch:

		$ curl http://fserver-1:9090/my_bucket/file1/attrs
		<attributes>
			<attribute name="color">blue</attribute>
			<attribute name="flavor">lemon</attribute>
		</attributes>

To set both of these attributes at once:

		$ curl -d color="blue" -d flavor="lemon" http://fserver-1:9090/my_bucket/file1/attrs

Single-attribute operations are also supported. To fetch a
single attribute:

		$ curl http://fserver-1:9090/my_bucket/file1/attr_color
		<attribute name="color">blue</attribute>

The attribute can also be set with a PUT to the same URL.

		$ printf green | curl -T - http://fserver-1:9090/my_bucket/file1/color

Lastly, objects and attributes can be deleted (object deletes
are propagated to secondary warehouses).

		$ curl -X DELETE http://fserver-1:9090/my_bucket/file2

Queries
-------

Queries are supported as in the design doc. Queries can contain
the following features, which are also supported for evaluating
replication policies:

* Literal integers, strings, and dates

* Object-attribute access: $attr

* Indirect object-attribute access: @link_on_cur_obj.link_target_attr

* Site-attribute access (for replication policies only):
  #attr

* Comparisons: <, <=, ==, !=, >=, >

* Booleans: &&, ||, !



The syntax to issue a query is as follows.

		$ curl -d '($color == "green") && ($flavor == "lemon")' \
		http://fserver-1:9090/my_bucket/_query
		<objects>
			<object>
				<bucket>my_bucket</bucket>
				<key>file1</key>
			</object>
		</objects>

Replication Policies
-------------------------------------------

Replication policies are stored as "_policy" attributes on
objects. To set a policy, use the same mechanism as for other attributes.

		$ printf '$color == "green"' | curl -T - http://fserver-1:9090/my_bucket/file1/_policy

This will cause the warehouse daemon to replicate to all secondary
warehouses whenever the object is changed (including attribute
changes) subsequently. You probably want to set the policy first,
before sending the body, and this is entirely allowable using
any of the attribute-setting mechanisms described above; this
would result in an empty object being created, then the subsequent
body PUT will be replicated. The above example is probably not
what you want for two other reasons:

1. Because the policy only refers to object attributes, it will
   replicate to all secondary warehouses.

2. It's cumbersome and inefficient to set separate replication
   policies for every object individually.



To specify selective replication, matching object atttributes
with secondary-warehouse attributes, you would do this instead.

		$ printf '$color == #color' | curl -T - http://fserver-1:9090/my_bucket/file1/_policy

To set a default replication policy for all objects within a bucket,
use the "_default" pseudo-object.

		$ printf '$color == #color' | curl -T - http://fserver-1:9090/my_bucket/_default/_policy

This will cause any modification to a green object to be replicated
to green remote warehouses any time they are changed, but will
not affect blue objects or purple warehouses. Note that the default
replication policy for a bucket is overridden by any specific
per-object policy.

Appendix 1: Major Divergences
-----------------------------

The current code doesn't implement exactly the API described
above. There are many differences in the exact format of data
returned for the API root, provider list, or object listings.
More importantly, the actual URLs and methods used for various
operations are still pending reconciliation with what's described
here. Here are the current equivalents, in approximately the
same order as mentioned above:

* bucket creation: PUT on .../my_bucket

* object-body fetch: GET on .../my_bucket/file1

* object-body store: PUT on .../my_bucket/file1

* multi-attribute set: POST on .../my_bucket with key=file1

* bucket and attribute deletes are not yet implemented



There are also a couple of special control operations, implemented
as POST methods on the object. The first of these is to force re-evaluation
of the relevant replication policies and trigger re-replication
to appropriate remote warehouses (equivalent to a PUT on the
object body except that there's no data transfer from the client).

		$ curl -d op=push http://fserver-1:9090/my_bucket/file1

The second control operation is used to determine whether replication
to a specific remote warehouse has finished.

		$ curl -d op=check loc=backup http://fserver-1:9090/my_bucket/file1

This will return a 404 (Not Found) if the object has not been replicated
to that location, or a 200 (OK) if it has.

Appendix 2: JSON Configuration Format
-------------------------------------

The initial configuration for the image warehouse is pulled
from a JSON configuration file, repo.json in the current directory
by default. This defines a set of required attributes plus any
others that the user might want to use in replication policies.
Here's an example:

		[
			{
				"name": "my tabled",
				"type": "s3",
				"host": "localhost",
				"port": 80,
				"key": "foo",
				"secret": "bar",
				"color": "blue"
			},
			{
				"name": "backup",
				"type": "http",
				"host": "localhost",
				"port": 9091
			}
		]

This defines a primary (local) warehouse named "my tabled" which
is using S3 on localhost. In this case the user name and password
are required - named "key" and "secret" in the file for legacy
reasons. We also have a secondary (remote) warehouse named "backup"
that we'll replicate to, and we don't care what back end it uses.
Since our interface to it is our own HTTP-based protocol, we don't
(currently) need a user name and password. Lastly, we've defined
our own "color" attribute to be used in making replication decisions.
