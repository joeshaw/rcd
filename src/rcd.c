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
#include <syslog.h>
#include <popt.h>


#include <glib.h>
#include <libredcarpet.h>

#include "rcd-about.h"
#include "rcd-log.h"
#include "rcd-module.h"
#include "rcd-query.h"
#include "rcd-rpc.h"
#include "rcd-rpc-packsys.h"
#include "rcd-rpc-log.h"
#include "rcd-rpc-news.h"
#include "rcd-rpc-prefs.h"
#include "rcd-transfer.h"
#include "rcd-subscriptions.h"
#include "rcd-fetch.h"
#include "rcd-heartbeat.h"

/* global variables related to option parsing */

static gboolean non_daemon_flag = FALSE;
static gboolean non_root_flag = FALSE;

static void
option_parsing (int argc, const char **argv)
{
    const struct poptOption command_line_options[] = {
        POPT_AUTOHELP
        { "non-daemon", 'n', POPT_ARG_NONE, &non_daemon_flag, 0,
          "Don't run the daemon in the background.", NULL },
        { "allow-non-root", '\0', POPT_ARG_NONE, &non_root_flag, 0,
          "Allow the daemon to be run as a user other than root.", NULL },
        POPT_TABLEEND
    };

    poptContext popt_context;
    int rv;

    popt_context = poptGetContext ("rcd",
                                   argc, argv,
                                   command_line_options, 0);
    while ( (rv = poptGetNextOpt (popt_context)) > 0);

    if (rv < -1) {
        g_printerr ("%s: %s\n", poptBadOption(popt_context, 0), poptStrerror (rv));
        g_printerr ("rcd aborting\n");
        exit (-1);
    }
}

static void
root_check (void)
{
    if (non_root_flag)
        return;

    /* Maybe-FIXME: Root always has a UID of zero, right? */
    if (getuid () == 0)
        return;

    g_printerr ("*** WARNING ***\n\n");
    g_printerr ("You have attempted to run rcd as a user other than 'root'.\n");
    g_printerr ("In general, this will not work -- rcd will be unable to modify\n");
    g_printerr ("the system to install, upgrade or remove packages.\n");
    g_printerr ("\n");
    g_printerr ("If you really want to do this, re-run rcd with the --allow-non-root\n");
    g_printerr ("option to suppress this warning message.  However, don't be surprised\n");
    g_printerr ("when rcd fails to work properly.\n");

    exit (-1);
}

static void
daemonize (void)
{
    int fork_rv;
    int i;

    if (non_daemon_flag)
        return;

    fork_rv = fork ();
    if (fork_rv < 0) {
        g_printerr ("rcd: fork failed!\n");
        exit (-1);
    }

    /* The parent exits. */
    if (fork_rv > 0)
        exit (0);
    
    /* A daemon should always be in its own process group. */
    setsid ();

    /* Close all file descriptors. */
    for (i = getdtablesize (); i >= 0; --i)
        close (i);

}

static void
debug_message_handler (const char *str, gpointer user_data)
{
    static int pid = 0;
    static FILE *out = NULL;

    if (pid == 0)
        pid = getpid ();

    if (out == NULL) {
        if (non_daemon_flag)
            out = stderr;
        else {
            out = fopen ("/tmp/rcd-messages", "a");
        }
    }

    fprintf (out, "[%d] %s\n", pid, str);
    fflush (out);
}

static void
initialize_logging (void)
{
    rcd_log_init (NULL); /* use default path */

    rc_debug_set_display_handler (debug_message_handler, NULL);
    rc_debug_set_display_level (RC_DEBUG_LEVEL_INFO);

    rc_debug (RC_DEBUG_LEVEL_ALWAYS, "%s", rcd_about_name ());
    rc_debug (RC_DEBUG_LEVEL_ALWAYS, "%s", rcd_about_copyright ());
    
    if (! non_daemon_flag) {
        openlog ("rcd", 0, LOG_DAEMON);
        syslog (LOG_INFO, "Starting %s", rcd_about_name());
        closelog ();
    }
    
} /* initialize_logging */

static void
initialize_rc_world (void)
{
    RCPackman *packman;
    RCWorld *world;

    /* Create a packman, hand it off to the world */
    packman = rc_distman_new ();
    if (! packman) {
        rc_debug(RC_DEBUG_LEVEL_ERROR, "Couldn't get a packman");
        exit (-1);
    }
    rc_packman_set_packman (packman);

    world = rc_get_world ();
    rc_world_register_packman (world, packman);
    rc_world_get_system_packages (world);
    
    
} /* initialize_rc_world */

static void
initialize_rpc (void)
{
    rcd_rpc_packsys_register_methods (rc_get_world ());
    rcd_rpc_log_register_methods ();
    rcd_rpc_news_register_methods ();
    rcd_rpc_prefs_register_methods ();
} /* initialize_rpc */

static void
initialize_data (void)
{
    if (!rcd_fetch_channel_list_local ())
        rcd_fetch_channel_list ();
    
    rcd_subscriptions_load ();
    
    /* This will fall back and download from the net if necessary */
    rcd_fetch_all_channels_local ();

    if (!rcd_fetch_news_local ())
        rcd_fetch_news ();
} /* initialze_data */


int
main (int argc, const char **argv)
{
    GMainLoop *main_loop;

    g_type_init ();

    option_parsing (argc, argv);

    root_check ();
    daemonize ();

    initialize_logging ();
    initialize_rc_world ();
    initialize_rpc ();
    initialize_data ();

    rcd_module_init ();

    rcd_rpc_server_start ();
    rcd_heartbeat_start ();

    main_loop = g_main_loop_new (NULL, TRUE);
    g_main_run (main_loop);

    return 0;
} /* main */
