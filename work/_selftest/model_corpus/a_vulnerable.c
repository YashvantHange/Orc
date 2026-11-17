/* a_vulnerable.c - FIXTURE A. The real defect. DO NOT FIX IT.
 *
 * The CVE-2026-109618 shape, reduced: the entry counter is incremented before the fallible key
 * allocation, so when that allocation takes the non-local exit the table counts a slot that was
 * never initialised - and the destructor walks the counter.
 *
 * Nothing in this file is a dangerous call. There is no sink to grep for. The bug is the
 * relationship between three places: the increment, the exit, and the walk.
 */
#include "arena.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CAP 16

typedef struct {
    char *key;          /* arena-owned */
    int   val;
} slot_t;

typedef struct {
    slot_t *slots;
    size_t  nNumUsed;   /* INVARIANT: counts only slots whose key is initialised */
} table_t;

static void table_init(table_t *t)
{
    /* malloc, not calloc: an uninitialised slot really is uninitialised, so MSAN can see the
     * read. With calloc the key would be a predictable NULL and the defect would hide. */
    t->slots = (slot_t *)malloc(sizeof(slot_t) * CAP);
    t->nNumUsed = 0;
}

/* The insert. Read it closely: every line is correct on its own. */
static void table_insert(table_t *t, arena_t *a, const char *key, int val)
{
    if (t->nNumUsed >= CAP)
        return;

    size_t i = t->nNumUsed++;        /* (1) the slot is counted BEFORE it exists */

    t->slots[i].key = arena_strdup(a, key);   /* (2) may never return - longjmp on OOM */
    t->slots[i].val = val;                    /*     so this, and the slot, stay unwritten */
}

/* The consumer, in a different function, reached by a different path. It trusts the counter. */
static void table_destroy(table_t *t)
{
    for (size_t i = 0; i < t->nNumUsed; i++) {
        /* (3) reads a key that (2) may never have written, and prints what it finds */
        if (t->slots[i].key != NULL)
            printf("  freeing key %s\n", t->slots[i].key);
    }
    free(t->slots);
    t->slots = NULL;
    t->nNumUsed = 0;
}

int main(int argc, char **argv)
{
    /* oom_after: how many arena allocations succeed before the next one bails. Choosing 2 makes
     * the third insert fail, so the table ends up counting a slot it never filled. */
    int oom_after = (argc > 1) ? atoi(argv[1]) : 2;

    char buf[1024];
    jmp_buf bail;
    arena_t a;
    table_t t;

    table_init(&t);
    arena_init(&a, buf, sizeof buf, &bail, oom_after);

    if (setjmp(bail) == 0) {
        table_insert(&t, &a, "alpha", 1);
        table_insert(&t, &a, "beta", 2);
        table_insert(&t, &a, "gamma", 3);
        table_insert(&t, &a, "delta", 4);
        printf("all inserts completed\n");
    } else {
        /* The bailout handler. It knows an allocation failed; it does NOT know the table was
         * mid-insert, and there is nothing here that could repair it. */
        printf("allocation failed - request aborted (nNumUsed=%zu)\n", t.nNumUsed);
    }

    /* Request shutdown, in the order a real one runs: the arena dies, then the structures that
     * pointed into it are torn down. */
    arena_reset(&a);
    table_destroy(&t);
    return 0;
}
