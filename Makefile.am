AM_CFLAGS	= -W -Wall -Wshadow -Wextra
AM_CPPFLAGS	= -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include

bin_PROGRAMS	= repod
repod_SOURCES = \
  meta.cpp	\
  meta.h	\
  proxy.c	\
  proxy.h	\
  query.c	\
  query.h	\
  repo.h	\
  rest.c	\
  template.c	\
  template.h

repod_CPPFLAGS	= @HAIL_CFLAGS@
repod_LDADD	= -lmongoclient \
		  @BOOST_FS_LIB@ @BOOST_PO_LIB@ @BOOST_SYS_LIB@ @BOOST_THR_LIB@\
		  @CRYPTO_LIB@ @CURL_LIB@ @JANSSON_LIB@ @UHTTPD_LIB@ \
		  @PTHREAD_LIB@ @XML2_LIB@ @GLIB2_LIB@ \
		  @HAIL_LIBS@
