/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-shutdown.c
 *
 * Copyright (C) 2002 Ximian, Inc.
 *
 */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA.
 */

#include <config.h>
#include <unistd.h>

#include <libredcarpet.h>

#include "rcd-options.h"
#include "rcd-shutdown.h"

typedef struct _ShutdownHandler ShutdownHandler;
struct _ShutdownHandler {
    RCDShutdownFn fn;
    gpointer user_data;
};

static GSList *shutdown_handlers = NULL;
static int shutdown_counter = 0;
static gboolean shutdown_pending = FALSE;
static gboolean shutting_down = FALSE;

void
rcd_shutdown_add_handler (RCDShutdownFn fn,
                          gpointer      user_data)
{
    ShutdownHandler *handler;

    g_return_if_fail (fn != NULL);

    handler = g_new0 (ShutdownHandler, 1);
    handler->fn = fn;
    handler->user_data = user_data;

    shutdown_handlers = g_slist_prepend (shutdown_handlers,
                                         handler);
}

void
rcd_shutdown_block (void)
{
    g_return_if_fail (shutdown_counter >= 0);

    if (shutting_down) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Attempting to block shut-down while shut-down is already in progress!");
    }
    ++shutdown_counter;
}

void
rcd_shutdown_allow (void)
{
    g_return_if_fail (shutdown_counter > 0);
    --shutdown_counter;

    if (shutdown_counter == 0 && shutdown_pending) {
        rcd_shutdown ();
    }
}

static gboolean
shutdown_idle_cb (gpointer user_data)
{
    gboolean restart = GPOINTER_TO_INT (user_data);
    GSList *iter;    

    for (iter = shutdown_handlers; iter != NULL; iter = iter->next) {
        ShutdownHandler *handler = iter->data;
        
        if (handler && handler->fn) 
            handler->fn (handler->user_data);

        g_free (handler);
    }

    g_slist_free (shutdown_handlers);

    if (!restart) {
        /* We should be quitting the main loop (which will cause us to
           exit) in a handler.  If not, we'll throw in an exit just to be
           sure. */
        exit (0);
    }
    else {
        const char **argv = rcd_options_get_argv ();

        execv (argv[0], (char **) argv);
    }

    /* We should never reach here... */
    return FALSE;
}

void
do_shutdown (gboolean restart)
{
    if (shutdown_counter > 0) {
        shutdown_pending = TRUE;
        return;
    }

    if (shutting_down) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Shut-down request received while shut-down is already in progress!");
        return;
    }

    shutting_down = TRUE;

    g_idle_add (shutdown_idle_cb, GINT_TO_POINTER (restart));
}

void
rcd_shutdown (void)
{
    do_shutdown (FALSE);
}

void
rcd_restart (void)
{
    do_shutdown (TRUE);
}
