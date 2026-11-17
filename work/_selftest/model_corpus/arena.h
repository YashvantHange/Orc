/* arena.h - a request-scoped arena allocator with a non-local failure path.
 *
 * DO NOT FIX ANYTHING IN THIS DIRECTORY. See README.md.
 *
 * This exists so the corpus has a REAL abnormal exit. A fixture whose allocation failure is just
 * a NULL return teaches the wrong lesson: the defect class needs a failure that abandons the
 * caller mid-statement, which is what longjmp (and PHP's zend_bailout, and Apache's abortfunc)
 * actually do. arena_alloc either returns memory or never returns at all.
 */
#ifndef ARENA_H
#define ARENA_H

#include <setjmp.h>
#include <stddef.h>

typedef struct {
    char   *base;
    size_t  cap;
    size_t  used;
    jmp_buf *bail;      /* where an allocation failure lands. Set by the request loop. */
    int     oom_after;   /* test hook: fail the Nth allocation. -1 = never fail. */
    int     allocs;
} arena_t;

void  arena_init(arena_t *a, char *buf, size_t cap, jmp_buf *bail, int oom_after);
void *arena_alloc(arena_t *a, size_t n);        /* never returns NULL: it longjmps instead */
char *arena_strdup(arena_t *a, const char *s);  /* same */
void  arena_reset(arena_t *a);                  /* end of request: every pointer into it dies */

#endif
