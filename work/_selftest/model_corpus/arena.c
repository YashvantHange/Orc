/* arena.c - see arena.h. DO NOT FIX ANYTHING IN THIS DIRECTORY. */
#include "arena.h"

#include <string.h>

void arena_init(arena_t *a, char *buf, size_t cap, jmp_buf *bail, int oom_after)
{
    a->base = buf;
    a->cap = cap;
    a->used = 0;
    a->bail = bail;
    a->oom_after = oom_after;
    a->allocs = 0;
}

void *arena_alloc(arena_t *a, size_t n)
{
    a->allocs++;
    /* The non-local exit. The caller does not get a chance to clean up after itself, which is the
     * whole point: whatever it had half-finished stays half-finished. */
    if (a->oom_after >= 0 && a->allocs > a->oom_after)
        longjmp(*a->bail, 1);
    if (a->used + n > a->cap)
        longjmp(*a->bail, 1);

    void *p = a->base + a->used;
    a->used += (n + 7u) & ~(size_t)7u;      /* keep 8-byte alignment */
    return p;
}

char *arena_strdup(arena_t *a, const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = (char *)arena_alloc(a, n);     /* may never return */
    memcpy(p, s, n);
    return p;
}

void arena_reset(arena_t *a)
{
    /* End of request. Every pointer anyone still holds into this arena is now dangling - the
     * memory is not returned to the OS, so a stale read sees whatever the NEXT request writes. */
    a->used = 0;
    a->allocs = 0;
}
