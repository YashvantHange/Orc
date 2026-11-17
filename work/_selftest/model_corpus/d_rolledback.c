/* d_rolledback.c - FIXTURE D. Abnormal exit DOES fire mid-mutation, and is correctly rolled
 * back. Must NOT be reported.
 *
 * The distinction this fixture forces: "an abnormal exit interrupts a partial mutation" is not
 * the defect. The defect is an interrupted mutation that nobody repairs. Here the bailout handler
 * is written to repair it, and it is the handler - not the insert - that holds the invariant.
 *
 * A method that reports this one has stopped one question early: it found the window and never
 * asked who cleans up after it. The answer is three lines away, in a different function.
 */
#include "arena.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CAP 16

typedef struct {
    char *key;
    int   val;
} slot_t;

typedef struct {
    slot_t *slots;
    size_t  nNumUsed;    /* INVARIANT: counts only slots whose key is initialised */
    size_t  committed;   /* the rollback point: nNumUsed as of the last whole insert */
} table_t;

static void table_init(table_t *t)
{
    t->slots = (slot_t *)malloc(sizeof(slot_t) * CAP);
    t->nNumUsed = 0;
    t->committed = 0;
}

/* Same increment-first shape as fixture A, same fallible call, same window. */
static void table_insert(table_t *t, arena_t *a, const char *key, int val)
{
    if (t->nNumUsed >= CAP)
        return;

    size_t i = t->nNumUsed++;

    t->slots[i].key = arena_strdup(a, key);   /* may never return */
    t->slots[i].val = val;

    t->committed = t->nNumUsed;                /* reached only when the slot is whole */
}

/* THE ROLLBACK. This is what makes the fixture safe, and it lives nowhere near the insert. */
static void table_rollback(table_t *t)
{
    /* Any slot above the last committed index was counted but never filled. Un-count it. */
    t->nNumUsed = t->committed;
}

static void table_destroy(table_t *t)
{
    for (size_t i = 0; i < t->nNumUsed; i++) {
        if (t->slots[i].key != NULL)
            printf("  freeing key %s\n", t->slots[i].key);
    }
    free(t->slots);
    t->slots = NULL;
    t->nNumUsed = 0;
}

int main(int argc, char **argv)
{
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
        table_rollback(&t);     /* <-- the invariant is restored before anything can read it */
        printf("allocation failed - rolled back to %zu entries\n", t.nNumUsed);
    }

    arena_reset(&a);
    table_destroy(&t);
    return 0;
}
