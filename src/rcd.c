/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd.c
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <popt.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>


#include <glib.h>
#include <libredcarpet.h>

#include "rcd-about.h"
#include "rcd-fetch.h"
#include "rcd-heartbeat.h"
#include "rcd-identity.h"
#include "rcd-log.h"
#include "rcd-module.h"
#include "rcd-privileges.h"
#include "rcd-query.h"
#include "rcd-rpc.h"
#include "rcd-rpc-packsys.h"
#include "rcd-rpc-log.h"
#include "rcd-rpc-news.h"
#include "rcd-rpc-prefs.h"
#include "rcd-rpc-users.h"
#include "rcd-shutdown.h"
#include "rcd-subscriptions.h"
#include "rcd-transfer.h"

/* global variables related to option parsing */

static gboolean non_daemon_flag = FALSE;
static gboolean non_root_flag = FALSE;
static int debug_level = RC_DEBUG_LEVEL_INFO;

static void
option_parsing (int argc, const char **argv)
{
    const struct poptOption command_line_options[] = {
        POPT_AUTOHELP
        { "non-daemon", 'n', POPT_ARG_NONE, &non_daemon_flag, 0,
          "Don't run the daemon in the background.", NULL },
        { "allow-non-root", '\0', POPT_ARG_NONE, &non_root_flag, 0,
          "Allow the daemon to be run as a user other than root.", NULL },
        { "debug", 'd', POPT_ARG_INT, &debug_level, 0,
          "Set the verbosity of debugging output.", NULL },
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
    /* Maybe-FIXME: Root always has a UID of zero, right? */
    if (getuid () == 0)
        return;

    g_printerr ("*** WARNING ***\n\n");
    g_printerr ("You have attempted to run rcd as a user other than 'root'.\n");
    g_printerr ("In general, this will not work -- rcd will be unable to modify\n");
    g_printerr ("the system to install, upgrade or remove packages.\n");
    g_printerr ("\n");

    if (! non_root_flag) {
        g_printerr ("If you really want to do this, re-run rcd with the --allow-non-root\n");
        g_printerr ("option to suppress this warning message.  However, don't be surprised\n");
        g_printerr ("when rcd fails to work properly.\n");
        exit (-1);
    }
}

static void
daemonize (void)
{
    int fork_rv;
    int i;
    int log_fd;

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

    open ("/dev/null", O_RDWR); /* open /dev/null as stdin*/

    /* Open a new file for our logging file descriptor. */
    log_fd = open ("/tmp/rcd-messages",
                   O_CREAT | O_APPEND,
                   S_IRUSR | S_IWUSR);

    dup (log_fd); /* dup log_fd to stdout */
    dup (log_fd); /* dup log_fd to stderr */
}

static void
debug_message_handler (const char *str, gpointer user_data)
{
    static int pid = 0;
    char *log_msg;

    if (pid == 0)
        pid = getpid ();

    log_msg = g_strdup_printf ("[%d] %s\n", pid, str);

    /* If we've daemonized, stderr has been redirected to the
       /tmp/rcd-messages file.  Since stderr might not actually
       be stderr, we also fsync. */
    write (STDERR_FILENO, log_msg, strlen (log_msg));
    fsync (STDERR_FILENO);

    g_free (log_msg);
}

static void
initialize_logging (void)
{
    rcd_log_init (NULL); /* use default path */

    rc_debug_set_display_handler (debug_message_handler, NULL);
    rc_debug_set_display_level (debug_level);

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
    rcd_rpc_users_register_methods ();
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

static void
signal_handler (int sig_num)
{
    const char *sig_name = NULL;

    if (sig_num == SIGQUIT)
        sig_name = "SIGQUIT";
    else if (sig_num == SIGTERM)
        sig_name = "SIGTERM";
    else
        g_assert_not_reached ();

    rc_debug (RC_DEBUG_LEVEL_INFO, "Received %s... Shutting down.", sig_name);
    rcd_shutdown ();
} /* signal_handler */

int
main (int argc, const char **argv)
{
    GMainLoop *main_loop;
    struct sigaction sig_action;

    g_type_init ();

    main_loop = g_main_loop_new (NULL, TRUE);
    rcd_shutdown_add_handler ((RCDShutdownFn) g_main_loop_quit,
                              main_loop);

    option_parsing (argc, argv);

    root_check ();
    daemonize ();

    /* Set up SIGTERM and SIGQUIT handlers */
    sig_action.sa_handler = signal_handler;
    sigemptyset (&sig_action.sa_mask);
    sig_action.sa_flags = 0;
    sigaction (SIGTERM, &sig_action, NULL);
    sigaction (SIGQUIT, &sig_action, NULL);

    rcd_privileges_init ();

    initialize_logging ();

    /* Check to see if the password file is secure.
       If it isn't, a big warning will go out to the log file. */
    rcd_identity_password_file_is_secure ();
    
    initialize_rc_world ();
    initialize_rpc ();
    initialize_data ();

    rcd_module_init ();

    rcd_rpc_server_start ();
    rcd_heartbeat_start ();

    g_main_run (main_loop);

    return 0;
} /* main */
