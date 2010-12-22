#include <string.h>
#define GC_THREADS
#include "gc.h"

#ifndef __cplusplus
# define malloc(n) GC_MALLOC(n)
# define calloc(m,n) GC_MALLOC((m)*(n))
# define free(p) GC_FREE(p)
# define realloc(p,n) GC_REALLOC((p),(n))
#endif

static inline char *
my_strdup (char const *s)
{
  size_t len = strlen (s);
  void *t = GC_MALLOC (len + 1);
  if (t == NULL)
    return NULL;
  return (char *) memcpy (t, s, len + 1);
}
# undef strdup
# define strdup(s) my_strdup(s)

static inline char *
my_strndup (char const *s, size_t n)
{
  size_t len = strnlen (s, n);
  char *t = (char *) GC_MALLOC (len + 1);
  if (t == NULL)
    return NULL;
  t[len] = '\0';
  return (char *) memcpy (t, s, len);
}
# undef strndup
# define strndup(s, n) my_strndup(s, n)
