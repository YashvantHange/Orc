/* c_suspicious.c - FIXTURE C. Looks exactly like fixture A. Is safe. Must NOT be reported.
 *
 * This is the fixture that decides whether the capability is real rather than pattern-matching.
 * It has the increment-before-allocation shape, in the same statement form A uses, and a
 * destructor that walks the same counter. Everything a pattern would key on is present.
 *
 * It is safe because the allocation it precedes CANNOT fail: the slot's key memory is reserved
 * out of a fixed per-slot buffer that was sized at init, so there is no fallible call between the
 * increment and the fully-written slot. The abnormal exit cannot land in the window, because
 * there is no window.
 *
 * A method that reports this one is producing false positives, and the reason matters: it means
 * the method matched the SHAPE and never asked whether the interrupt can actually occur there.
 */
#include "arena.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CAP     16
#define KEYMAX  32

typedef struct {
    char key[KEYMAX];       /* inline storage: no allocation, nothing to fail */
    int  val;
} slot_t;

typedef struct {
    slot_t *slots;
    size_t  nNumUsed;       /* INVARIANT: counts only slots whose key is initialised */
} table_t;

static void table_init(table_t *t)
{
    t->slots = (slot_t *)malloc(sizeof(slot_t) * CAP);
    t->nNumUsed = 0;
}

static void table_insert(table_t *t, arena_t *a, const char *key, int val)
{
    (void)a;                 /* the arena is deliberately not used for the key */
    if (t->nNumUsed >= CAP)
        return;

    size_t i = t->nNumUsed++;    /* same increment-first shape as fixture A */

    /* ...but the write is a bounded memcpy into storage that already exists. No allocation, no
     * longjmp, no window. strncpy's truncation is a correctness wart, not a lifetime bug. */
    strncpy(t->slots[i].key, key, KEYMAX - 1);
    t->slots[i].key[KEYMAX - 1] = '\0';
    t->slots[i].val = val;
}

static void table_destroy(table_t *t)
{
    for (size_t i = 0; i < t->nNumUsed; i++)      /* walks the count, exactly like A */
        printf("  dropping key %s\n", t->slots[i].key);
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
