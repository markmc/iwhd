Notes on registration in iwhd
=============================

Every known cloud incudes a concept known as "registration", when an image
requires special processing before it can be instantiated. Generally, if
iwhd runs on host H, and cloud includes a storage back-end S and a management
server M, the registration involves:
 - formatting the image, if necessary
 - generating any necessary manifests, metadata, or OVF files
 - uploading the image from H to S
 - notifying M with an API call

The registration is triggered with "op=register" posted to iwhd image.
Unfortunately, paramteres are cloud-specific (see examples).

When registrarion completes with code 200, application is supposed to
extract a cloud ID from the "ami-id" attribute, and verify that it starts
with "OK". For example:
 curl http://iwhdhost.eng.example.com:9090/buk1/test_img/ami-id

Another unfortunate implementation limitation is that registrations are
going to fail unless iwhd uses a filesystem-type back-end. A work is ongoing
to lift this restriction.

Amazon EC2
----------

There is no pre-set except configuring iwhd/conf.js like so:

[
   {
      "name": "main",
      "type": "fs",
      "path": "_fs",
   }
]

Note that the type is "fs", not "s3" (see the second unfortunate note above).

Registration call:

 curl -d op=register -d site=amazon \
  -d api-key=AKIAJAJZYB6229Z5K3VW \
  -d api-secret=PPU45khle/uHqq0xGPNNSJLAmPwsc9end7s3aCx+ \
  -d ami-cert=/home/tester/cert-1.pem \
  -d ami-key=/home/tester/pk-1.pem \
  -d ami-uid=089534962013 \
  -d ami-bkt=west-test \
  -d kernel=_default_ \
  -d ramdisk=_default_ \
  http://localhost:9090/buk1/dummy_img

Note that S3 bucket may be different from iwhd bucket. This is mostly done
because Amazon buckets are global and it is very easy to run into conflicts.
The kernel and ramdisk arguments are optional.

The ami-id contains a pattern like "OK ami-298f1573".

This back-end may be compatible with Amazonesque clouds, such as Eucalyptus
and OpenStack.

RHEV-M
------

The pre-set for RHEV-M consists of creating an NFS area (S) that both RHEV-M
server (M) and iwhd server (H) can access for writing. Its top-level directory
must be owned by user 36 (vdsm) and group 36 (kvm). Usually the /etc/exports
looks like this:

 /home/vdsm  10.16.0.0/16(rw) 10.11.10.167/16(rw) *(ro)

This assumes iwhd is ran as root. Since iwhd must write into the area S
with UID 36, attempts to run iwhd as non-priviledeged user require
tricks with wrapping dc-rhev-image into a script that calls sudo.
Do not attempt it if you value your sanity.

The area S must be mounted at H (example below assumes /mnt/iwhd-fish).
For the curl example below, mount like this:
 mount -t nfs -o v3 fish.usersys.redhat.com:/home/vdsm/v1 /mnt/iwhd-fish

In RHEL 6 and Fedora 14, NFS mounts default to v4, which causes some
weird file ownership issues. Verify by checking what RHEV-M created
on the next step. The /mnt/iwhd-fish should contain files owned by vdsm.
Note that this has nothing to do with root_squash.

Finally, RHEV-M must be told to "import" and "attach" so-called
"export storage domain". At this time, RHEV-M server mounts the area S
and creates the necessary directory structure. The names it selects are
impossible to guess ahead, so this must be done before any registrations
are attempted. Only then iwhd is able to store anything into S.

The provider in iwhd/conf.js uses "fs-rhev-m" type:

[
   {
      "name": "main",
      "type": "fs-rhev-m",
      "path": "_fs",
   }
]

Registration call:

 curl -d op=register -d site=main \
  -d api-url=http://rhevm23.virt.lab.eng.bos.redhat.com/rhevm-api \
  -d api-key=rhevadmin@virt.lab.eng.bos.redhat.com \
  -d api-secret=donotusepassw0rd \
  -d nfs-host=fish.usersys.redhat.com \
  -d nfs-path=/home/vdsm/v1 \
  -d nfs-dir=/mnt/iwhd-fish \
  http://localhost:9090/buk1/dummy_img

The ami-id contains a pattern like "OK <uuid>". The UUID is the "image"
UUID that can be used to find the image by RHEV-M datacenters through
its RESTful API.

Condor
------

Condor is a toy cloud that DeltaCloud use for testing.

Condor uses NFS just like RHEV-M, but there are no problems with UID 36,
so iwhd can be run as non-root. The only requirement is to create a
subdirectory called "staging/" in area S, and make sure that iwhd can
write into S.

The area S must be mounted at H, of course.

[
   {
      "name": "condor",
      "type": "fs-condor",
      "path": "/home/iwhd/_fs",
   }
]

Registration call:

 curl -d op=register -d site=main \
  -d nfs-dir=/mnt/falcon-in \
  http://localhost:9090/buk1/dummy_img_2

This basically copies the image into /mnt/falcon-in/staging/, then
renames it into /mnt/falcon-in/.

VMware vSphere
--------------

Registration in vSphere requires no presets. Unfortunately, one still has
to select the appropriate "VM host" among those that given vSphere manages.
The VM image is going to be registered in vSphere as a whole, but uploaded
to the specific host.

[
   {
      "name": "main",
      "type": "fs-vmw",
      "path": "_fs",
   }
]

Registration call:

 curl -d op=register -d site=main \
  -d api-url=https://vsphere.virt.bos.redhat.com/sdk \
  -d api-key=Administrator@virt.lab.eng.bos.redhat.com \
  -d api-secret=donotusepassw0rd \
  -d vm-name=dummy_img_3 \
  -d vm-host=virtlab110.virt.bos.redhat.com \
  http://localhost:9090/buk1/dummy_img_3

The VM name has to be unique in the vSphere environment. If not set, the
image's key is used.

The ami-id contains a pattern like "OK name:dummy_img_3". The "name:"
selector is supposed to provide a measure of compatibility for the future,
in case we ever decide to return a MOR or UUID.
