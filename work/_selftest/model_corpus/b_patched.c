/* b_patched.c - FIXTURE B. Fixture A with the real fix applied. Must NOT be reported.
 *
 * This is the control that catches a method which points at a famous function rather than at a
 * defect. The invariant is the same sentence; here it holds, so the honest verdict is `no` WITH
 * the citation of the line that makes it hold.
 *
 * The fix is the one upstream made: allocate first, commit the counter only on success.
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
    size_t  nNumUsed;   /* INVARIANT: counts only slots whose key is initialised */
} table_t;

static void table_init(table_t *t)
{
    t->slots = (slot_t *)malloc(sizeof(slot_t) * CAP);
    t->nNumUsed = 0;
}

static void table_insert(table_t *t, arena_t *a, const char *key, int val)
{
    if (t->nNumUsed >= CAP)
        return;

    /* THE FIX: the fallible call happens into a local. If it never returns, the table has not
     * been touched at all, so the invariant cannot be observed broken. */
    char *k = arena_strdup(a, key);

    size_t i = t->nNumUsed;
    t->slots[i].key = k;
    t->slots[i].val = val;
    t->nNumUsed = i + 1;      /* the counter commits LAST, after the slot is whole */
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
        printf("allocation failed - request aborted (nNumUsed=%zu)\n", t.nNumUsed);
    }

    arena_reset(&a);
    table_destroy(&t);
    return 0;
}
