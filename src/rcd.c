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
#include <uuid/uuid.h>

#include "rcd-about.h"
#include "rcd-fetch.h"
#include "rcd-heartbeat.h"
#include "rcd-identity.h"
#include "rcd-log.h"
#include "rcd-module.h"
#include "rcd-prefs.h"
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
static gboolean late_background = FALSE;
static gboolean non_root_flag = FALSE;
static int remote_port = 0;
static gboolean remote_disable = FALSE;
static char *dump_file = NULL;

static void
option_parsing (int argc, const char **argv)
{
    gint debug_level = -1, syslog_level = -1;

    const struct poptOption command_line_options[] = {
        POPT_AUTOHELP
        { "non-daemon", 'n', POPT_ARG_NONE, &non_daemon_flag, 0,
          "Don't run the daemon in the background.", NULL },
        { "late-background", '\0', POPT_ARG_NONE, &late_background, 0,
          "Run the daemon in the background, but not until it is ready to accept connections.", NULL },
        { "allow-non-root", '\0', POPT_ARG_NONE, &non_root_flag, 0,
          "Allow the daemon to be run as a user other than root.", NULL },
        { "port", 'p', POPT_ARG_INT, &remote_port, 0,
          "Listen for remote connections on a different port", NULL },
        { "no-remote", 'r', POPT_ARG_NONE, &remote_disable, 0,
          "Don't listen for remote connections", NULL },
        { "debug", 'd', POPT_ARG_INT, &debug_level, 0,
          "Set the verbosity of debugging output.", NULL },
        { "syslog", 's', POPT_ARG_INT, &syslog_level, 0,
          "Set the verbosity of syslog output.", NULL },
        { "undump", '\0', POPT_ARG_STRING, &dump_file, 0,
          "Initialize daemon from a dump file.", "filename" },
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

    if (getenv ("RCD_NON_DAEMON"))
        non_daemon_flag = TRUE;

    if (debug_level > -1)
        rcd_prefs_set_debug_level (debug_level);
    if (syslog_level > -1)
        rcd_prefs_set_syslog_level (syslog_level);
}

static void
root_check (void)
{
    /* Not being root is fine when we initialize from a dump file. */
    if (dump_file != NULL)
        return;

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

static int pid_for_messages = 0;

static void
debug_message_handler (const char *str, RCDebugLevel level, gpointer user_data)
{
    char *log_msg;

    if (pid_for_messages == 0)
        pid_for_messages = getpid ();

    log_msg = g_strdup_printf ("[%d] %s\n", pid_for_messages, str);

    if (level <= rcd_prefs_get_debug_level ()) {
        /* If we've daemonized, stderr has been redirected to the
           /tmp/rcd-messages file.  Since stderr might not actually
           be stderr, we also fsync. */
        write (STDERR_FILENO, log_msg, strlen (log_msg));
        fsync (STDERR_FILENO);
    }

    /* FIXME: Use RCDebug's display_level instead of hardcoding value here? */
    if (!non_daemon_flag && level <= rcd_prefs_get_syslog_level ()) {
        openlog ("rcd", 0, LOG_DAEMON);
        syslog (LOG_INFO, "%s", log_msg);
        closelog ();
    }

    g_free (log_msg);
}

static void
hello (void)
{
    time_t t;
    char *time_str;
    
    rc_debug (RC_DEBUG_LEVEL_ALWAYS, "%s", rcd_about_name ());
    rc_debug (RC_DEBUG_LEVEL_ALWAYS, "%s", rcd_about_copyright ());

    time (&t);
    time_str = ctime (&t);
    time_str[strlen(time_str)-1] = '\0'; /* trim off the newline */

    rc_debug (RC_DEBUG_LEVEL_ALWAYS, "Start time: %s", time_str);
}

static void
initialize_logging (void)
{
    rcd_log_init (NULL); /* use default path */

    rc_debug_add_handler (debug_message_handler, RC_DEBUG_LEVEL_ALWAYS, NULL);

    hello ();

} /* initialize_logging */

static void
daemonize (void)
{
    int fork_rv;
    int i;
    int log_fd;
    
    /* We never daemonize when we initialize from a dump file. */
    if (dump_file != NULL)
        return;

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

    /* Clear out the PID, just in case we are daemonizing late. */
    pid_for_messages = 0;
    
    /* A daemon should always be in its own process group. */
    setsid ();

    /* Close all file descriptors. */
    for (i = getdtablesize (); i >= 0; --i)
        close (i);

    open ("/dev/null", O_RDWR); /* open /dev/null as stdin */

    if (! g_file_test ("/var/log/rcd", G_FILE_TEST_EXISTS)) {
        if (mkdir ("/var/log/rcd",
                   S_IRUSR | S_IWUSR | S_IXUSR |
                   S_IRGRP | S_IXGRP |
                   S_IROTH | S_IXOTH) != 0) {
            rc_debug (RC_DEBUG_LEVEL_WARNING,
                      "Can't create directory '/var/log/rcd'");
        }
    }
    
    /* Open a new file for our logging file descriptor.  This
       will be the fd 1, stdout. */
    log_fd = open ("/var/log/rcd/rcd-messages",
                   O_WRONLY | O_CREAT | O_APPEND,
                   S_IRUSR | S_IWUSR);
    
    dup (log_fd); /* dup log_fd to stdout */
}

static void
shutdown_world (gpointer user_data)
{
    RCWorld *world = user_data;
    
    rc_world_free (world);
}

static void
initialize_rc_world (void)
{
    RCPackman *packman;
    RCWorld *world;

    /* Create a packman, hand it off to the world */
    packman = rc_distman_new ();
    if (! packman) {
        rc_debug (RC_DEBUG_LEVEL_ERROR, "Couldn't get a packman");
        exit (-1);
    }

    if (rc_packman_get_error (packman)) {
        rc_debug (RC_DEBUG_LEVEL_ERROR,
                  "Couldn't access the packaging system: %s",
                  rc_packman_get_reason (packman));
        exit (-1);
    }

    rc_packman_set_packman (packman);

    world = rc_get_world ();
    rc_world_register_packman (world, packman);
    
    rcd_shutdown_add_handler (shutdown_world, world);

    if (dump_file != NULL) {
        char *dump_file_contents;

        rc_debug (RC_DEBUG_LEVEL_MESSAGE,
                  "Loading dump file '%s'",
                  dump_file);
        
        if (! g_file_get_contents (dump_file,
                                   &dump_file_contents,
                                   NULL, NULL)) {
            rc_debug (RC_DEBUG_LEVEL_ERROR,
                      "Unable to load dump file '%s'",
                      dump_file);

            exit (-1);
        }

        rc_world_undump (world, dump_file_contents);

        g_free (dump_file_contents);


    } else {

        rc_world_get_system_packages (world);
        
    }
    
    
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
rcd_create_uuid (const char *file)
{
    uuid_t uuid;
    char *out;
    char *dir;
    FILE *f;

    out = g_malloc0 (37);
    uuid_generate_random (uuid);
    uuid_unparse (uuid, out);

    dir = g_path_get_dirname (file);
    rc_mkdir (dir, 0755);
    g_free (dir);

    f = fopen (file, "w");
    if (!f) {
        rc_debug (RC_DEBUG_LEVEL_WARNING, "Unable to create machine ID");
        g_free (out);
        return;
    }

    fwrite (out, 37, 1, f);
    fflush (f);
    fclose (f);

    chmod (file, 0600);
} /* rcd_create_uuid */

static void
initialize_data (void)
{
    /* If we have loaded a dump file, we don't want to initialize
       any of this stuff. */
    if (dump_file != NULL)
        return;

    if (!rcd_fetch_channel_list_local ())
        rcd_fetch_channel_list ();
    
    rcd_subscriptions_load ();
    
    if (!g_file_test (SYSCONFDIR "/mcookie", G_FILE_TEST_EXISTS))
        rcd_create_uuid (SYSCONFDIR "/mcookie");

    if (!g_file_test (SYSCONFDIR "/partnernet", G_FILE_TEST_EXISTS))
        rcd_create_uuid (SYSCONFDIR "/partnernet");

    /*
     * We only want to do this when:
     *
     *    - We are in premium mode.
     *    - We have an organization ID set in our config file.
     *    - We have not previously registered, or we're forcing
     *      re-registration.
     */
    if (rcd_prefs_get_premium () &&
        rcd_prefs_get_org_id () &&
        (!rcd_prefs_get_registered () || getenv ("RCX_FORCE_REGISTRATION")))
        rcd_fetch_register ();

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
    else if (sig_num == SIGINT)
        sig_name = "SIGINT";
    else
        g_assert_not_reached ();

    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Received %s... Shutting down.", sig_name);
    rcd_shutdown ();
} /* signal_handler */

static void
crash_handler (int sig_num)
{
    char cmd[128];

    write (2, "Crash!\n", 7);
    
    /* FIXME: Just to be sure, we should drop privileges before doing
       this. */
    sprintf (cmd, "python " SHAREDIR "/rcd-buddy %d", getpid ());
    system (cmd);
    
    exit (1);
}

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

    /* FIXME: needs to be done right */
    if (!rc_distro_parse_xml (NULL, 0)) {
        exit (-1);
    }

    root_check ();
    if (! late_background)
        daemonize ();

    /* Set up SIGTERM and SIGQUIT handlers */
    sig_action.sa_handler = signal_handler;
    sigemptyset (&sig_action.sa_mask);
    sig_action.sa_flags = 0;
    sigaction (SIGINT,  &sig_action, NULL);
    sigaction (SIGTERM, &sig_action, NULL);
    sigaction (SIGQUIT, &sig_action, NULL);
    
    /* If it looks like rcd-buddy is in the right place, set up
       handlers for crashes */
    if (g_file_test (SHAREDIR "/rcd-buddy", G_FILE_TEST_EXISTS)
        && g_find_program_in_path ("python")) {
        sig_action.sa_handler = crash_handler;
        sigaction (SIGSEGV, &sig_action, NULL);
        sigaction (SIGFPE,  &sig_action, NULL);
        sigaction (SIGBUS,  &sig_action, NULL);
    }

    rcd_privileges_init ();

    initialize_logging ();

    /* Check to see if the password file is secure.
       If it isn't, a big warning will go out to the log file. */
    rcd_identity_password_file_is_secure ();
    
    initialize_rc_world ();
    initialize_rpc ();
    initialize_data ();
    
    /* We can't daemonize any later than this, so hopefully module initialization
       won't be slow. */
    if (late_background) {
        
        rc_debug (RC_DEBUG_LEVEL_ALWAYS, "Running daemon in background.");
        daemonize ();

        /* We need to reinit logging, since the file descriptor gets closed
           when we daemonize. */
        rcd_log_reinit ();

        /* Say hello again, so it gets stored in the log file. */
        hello ();
    }

    rcd_module_init ();

    if (remote_disable)
        remote_port = -1;

    rcd_rpc_server_start (remote_port);

    /* No heartbeat if we have initialized from a dump file. */
    if (dump_file == NULL)
        rcd_heartbeat_start ();

    g_main_run (main_loop);

    return 0;
} /* main */
