/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd.c
 *
 * Copyright (C) 2002 Ximian, Inc.
 *
 */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License, version 2,
 * as published by the Free Software Foundation.
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

#include <sys/types.h>
#include <unistd.h>

#include <glib.h>
#include <libredcarpet.h>

#include "rcd-module.h"
#include "rcd-query.h"
#include "rcd-rpc.h"
#include "rcd-rpc-packsys.h"
#include "rcd-transfer.h"
#include "rcd-fetch.h"

static void
debug_message_handler (const char *str, gpointer user_data)
{
    static int pid = 0;
    if (pid == 0)
        pid = getpid ();

    fprintf (stderr, "[%d] %s\n", pid, str);
}

static void
initialize_logging (void)
{
    rc_debug_set_display_handler (debug_message_handler, NULL);
    rc_debug_set_display_level (RC_DEBUG_LEVEL_INFO);

    rc_debug (RC_DEBUG_LEVEL_ALWAYS, "Starting Red Carpet Daemon " VERSION);
    rc_debug (RC_DEBUG_LEVEL_ALWAYS, "Copyright (C) 2000-2002 Ximian Inc.  All rights reserved.");
}

static void
initialize_rc_world (void)
{
    RCPackman *packman;
    RCWorld *world;

    /* Create a packman, hand it off to the world */
    packman = rc_distman_new ();
    if (!packman)
        g_error("Couldn't get a packman");
    rc_packman_set_packman (packman);

    world = rc_get_world ();
    rc_world_register_packman (world, packman);
    rc_world_get_system_packages (world);

    rcd_rpc_packsys_register_methods (world);

    /* rcd_query_test (); */

} /* initialize_rc_world */

int
main (int argc, char *argv[])
{
    GMainLoop *main_loop;

    g_type_init ();

    initialize_logging ();

    rcd_fetch_channel_list ();
    rcd_fetch_all_channels ();

    rcd_module_init ();
    initialize_rc_world ();

    main_loop = g_main_loop_new (NULL, TRUE);
    g_main_run (main_loop);

    return 0;
} /* main */
