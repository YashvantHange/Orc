/* e_crossscope.c - FIXTURE E. A process-lifetime global DOES hold request-arena memory. It is
 * safe. Must NOT be reported.
 *
 * This is the CVE-2026-109619 shape with the missing piece present: the global is cleared in the
 * request-shutdown path, before the arena is reset. Two requests run here, so a stale read would
 * actually be observable if one existed.
 *
 * The question this fixture forces is the one the whole family turns on, and it cannot be
 * answered by looking at the assignment: is the field nulled in the shutdown handler? That is a
 * DIFFERENT function, and the absence of a store is not something a pattern can see. A method that
 * reports this one never opened the shutdown path.
 */
#include "arena.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Process-lifetime storage, in the accessor-macro style a real runtime uses. */
typedef struct {
    char *last_upload_name;   /* points INTO the request arena while a request is live */
    int   request_count;      /* genuinely process-scoped: must NOT be cleared per request */
} module_globals_t;

static module_globals_t module_globals;
#define MG(v) (module_globals.v)

/* Per-request init. */
static void rinit(void)
{
    MG(last_upload_name) = NULL;
}

/* The handler. Assigns arena memory - request lifetime - into a global - process lifetime. */
static void handle_request(arena_t *a, const char *upload_name)
{
    MG(request_count)++;
    MG(last_upload_name) = arena_strdup(a, upload_name);   /* the cross-scope store */

    if (MG(last_upload_name) != NULL)
        printf("  request %d: upload %s\n", MG(request_count), MG(last_upload_name));
}

/* Per-request shutdown. THE LINE THAT MAKES THIS SAFE, and it is not next to the store. */
static void rshutdown(arena_t *a)
{
    MG(last_upload_name) = NULL;    /* cleared BEFORE the memory it points at goes away */
    arena_reset(a);
    /* request_count is deliberately NOT cleared: it is process-scoped by design, and a method
     * that flags it has confused "a global that is written during a request" with "a global that
     * holds request-scoped data". */
}

int main(int argc, char **argv)
{
    int oom_after = (argc > 1) ? atoi(argv[1]) : -1;

    char buf[1024];
    jmp_buf bail;
    arena_t a;

    arena_init(&a, buf, sizeof buf, &bail, oom_after);

    for (int i = 0; i < 2; i++) {
        rinit();
        if (setjmp(bail) == 0) {
            handle_request(&a, (i == 0) ? "first.bin" : "second.bin");
        } else {
            printf("  request %d aborted\n", MG(request_count));
        }
        rshutdown(&a);

        /* A stale read would show up here if the global still pointed into the reset arena. */
        printf("  after shutdown: last_upload_name=%s\n",
               MG(last_upload_name) ? MG(last_upload_name) : "(null)");
    }

    printf("served %d requests\n", MG(request_count));
    return 0;
}
