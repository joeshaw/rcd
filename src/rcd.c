/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd.c
 *
 * Copyright (C) 2002-2003 Ximian, Inc.
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
#include <signal.h>
#include <syslog.h>
#include <unistd.h>

#include <glib.h>
#include <libredcarpet.h>
#include <uuid/uuid.h>

#include "rcd-about.h"
#include "rcd-heartbeat.h"
#include "rcd-identity.h"
#include "rcd-log.h"
#include "rcd-module.h"
#include "rcd-options.h"
#include "rcd-package-locks.h"
#include "rcd-prefs.h"
#include "rcd-privileges.h"
#include "rcd-query.h"
#include "rcd-rpc.h"
#include "rcd-rpc-license.h"
#include "rcd-rpc-log.h"
#include "rcd-rpc-news.h"
#include "rcd-rpc-packsys.h"
#include "rcd-rpc-prefs.h"
#include "rcd-rpc-service.h"
#include "rcd-rpc-users.h"
#include "rcd-services.h"
#include "rcd-shutdown.h"
#include "rcd-transaction.h"
#include "rcd-transfer.h"
#include "rcd-world-remote.h"

#define SYNTHETIC_PACKAGE_DB_PATH "/var/lib/rcd/synthetic-packages.xml"

static gchar *rcd_executable_name = NULL;
static int pid_for_messages = 0;

static void
root_check (void)
{
    /* Not being root is fine when we initialize from a dump file. */
    if (rcd_options_get_dump_file () != NULL)
        return;

    if (getuid () == 0)
        return;

    g_printerr ("*** WARNING ***\n\n");
    g_printerr ("You have attempted to run rcd as a user other than "
                "'root'.\n");
    g_printerr ("In general, this will not work -- rcd will be unable to "
                "modify\n");
    g_printerr ("the system to install, upgrade or remove packages.\n");
    g_printerr ("\n");

    if (!rcd_options_get_non_root_flag ()) {
        g_printerr ("If you really want to do this, re-run rcd with the "
                    "--allow-non-root\n");
        g_printerr ("option to suppress this warning message.  However, "
                    "don't be surprised\n");
        g_printerr ("when rcd fails to work properly.\n");
        exit (-1);
    }
}

static void
debug_message_handler (const char *str, RCDebugLevel level, gpointer user_data)
{
    if (pid_for_messages == 0)
        pid_for_messages = getpid ();

    if (level <= rcd_prefs_get_debug_level ()) {
        struct tm *tm;
        time_t now;
        char timestr[128];
        char *log_msg;

        time (&now);
        tm = localtime (&now);
        strftime (timestr, 128, "%b %e %T", tm);

        log_msg = g_strdup_printf ("%s [%d] %s\n",
                                   timestr, pid_for_messages, str);
        /* If we've daemonized, stderr has been redirected to the
           /tmp/rcd-messages file.  Since stderr might not actually
           be stderr, we also fsync. */
        write (STDERR_FILENO, log_msg, strlen (log_msg));
        fsync (STDERR_FILENO);

        g_free (log_msg);
    }

    /* FIXME: Use RCDebug's display_level instead of hardcoding value here? */
    if (!rcd_options_get_non_daemon_flag () &&
        level <= rcd_prefs_get_syslog_level ()) {
        char *log_name = g_strdup_printf ("rcd[%d]", pid_for_messages);

        openlog (log_name, 0, LOG_DAEMON);
        syslog (LOG_INFO, "%s", str);
        closelog ();
        g_free (log_name);
    }
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
    int fd;
    char *pid;
    
    /* We never daemonize when we initialize from a dump file. */
    if (rcd_options_get_dump_file () != NULL)
        return;

    if (rcd_options_get_non_daemon_flag ())
        return;
#ifdef NEED_KERNEL_FD_WORKAROUND
   /*
    * This is an evil hack and I hate it, but it works around a broken ass
    * kernel bug.
    */
   for (i = 0; i < 256; i++) fopen ("/dev/null", "r");
#endif

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

    /* Change our CWD to / */
    chdir ("/");

    /* Close all file descriptors. */
    for (i = getdtablesize (); i >= 0; --i)
        close (i);

    fd = open ("/dev/null", O_RDWR); /* open /dev/null as stdin */
    g_assert (fd == STDIN_FILENO);

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
    fd = open ("/var/log/rcd/rcd-messages",
               O_WRONLY | O_CREAT | O_APPEND,
               S_IRUSR | S_IWUSR);
    g_assert (fd == STDOUT_FILENO);
    
    fd = dup (fd); /* dup fd to stderr */
    g_assert (fd == STDERR_FILENO);

    /* Open /var/run/rcd.pid and write out our PID */
    fd = open ("/var/run/rcd.pid", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    pid = g_strdup_printf ("%d", getpid ());
    rc_write (fd, pid, strlen (pid));
    g_free (pid);
    close (fd);

    rcd_shutdown_add_handler ((RCDHeartbeatFunc) unlink, "/var/run/rcd.pid");
}

static void
initialize_rc_services (void)
{
    rc_world_system_register_service ();
    rc_world_synthetic_register_service ();
    rc_world_local_dir_register_service ();
    rcd_world_remote_register_service ();
}

static void
shutdown_world (gpointer user_data)
{
    rc_set_world (NULL);

    /* FIXME: Remove for release */
    rc_package_spew_leaks ();
}

static void
shutdown_packman (gpointer user_data)
{
    rc_packman_set_global (NULL);
}

static void
initialize_rc_packman (void)
{
    RCPackman *packman;

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

    rcd_shutdown_add_handler (shutdown_packman, packman);
    rc_packman_set_global (packman);
    g_object_unref (packman);
}

static void
initialize_rc_world (void)
{

    RCWorld *world;
    const char *dump_file;

    /* Construct a multi-world */
    world = rc_world_multi_new ();

    /* If we are undumping, create and register an undump world. */
    dump_file = rcd_options_get_dump_file ();
    if (dump_file != NULL) {
        RCWorld *undump_world;

        rc_debug (RC_DEBUG_LEVEL_MESSAGE,
                  "Loading dump file '%s'",
                  dump_file);

        undump_world = rc_world_undump_new (dump_file);
        
        if (undump_world == NULL) {
            rc_debug (RC_DEBUG_LEVEL_ERROR,
                      "Unable to load dump file '%s'",
                      dump_file);
            exit (-1);
        }

        rc_world_multi_add_subworld (RC_WORLD_MULTI (world), undump_world);
        g_object_unref (undump_world);
    } 

    rcd_shutdown_add_handler (shutdown_world, world);
    rc_set_world (world);
    g_object_unref (world);
}

static void
initialize_rpc (void)
{
    rcd_rpc_packsys_register_methods (rc_get_world ());
    rcd_rpc_license_register_methods ();
    rcd_rpc_log_register_methods ();
    rcd_rpc_news_register_methods ();
    rcd_rpc_prefs_register_methods ();
    rcd_rpc_users_register_methods ();
    rcd_rpc_service_register_methods ();
} /* initialize_rpc */

static void
initialize_data (void)
{
    /* If we have loaded a dump file, we don't want to initialize
       any of this stuff. */
    if (rcd_options_get_dump_file () != NULL)
        return;

    /* Load the channel data from the services */
    rcd_services_load (RC_WORLD_MULTI (rc_get_world ()));

    /* This forces the subscriptions to be loaded from disk. */
    rc_subscription_get_status (NULL);

    /* We don't want to read in the locks until after we have fetched the
       list of channels. */
    rcd_package_locks_load (rc_get_world ());
} /* initialize_data */

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

    rc_debug (RC_DEBUG_LEVEL_MESSAGE,
              "Received %s... Shutting down.", sig_name);
    rcd_shutdown ();
} /* signal_handler */

static gboolean
rehash_data (gpointer data)
{
    /*
     * We don't want to rehash all of the data underneath ourselves if we're
     * in the middle of a transaction.  If we're locked, defer refreshing
     * until later.
     *
     * We keep around a timeout_id so if we get multiple HUPs we don't
     * defer the rehashing more than once.  That's just silly!
     */

    static int timeout_id = -1;

    if (!rcd_transaction_is_locked ()) {
        timeout_id = -1;
        rc_world_refresh (rc_get_world ());
    }
    else {
        if (timeout_id == -1)
            timeout_id = g_timeout_add (2000, rehash_data, NULL);
    }

    return FALSE;
} /* rehash_data */

static void
sighup_handler (int sig_num)
{
    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "SIGHUP received; reloading data");

    if (!rcd_options_get_non_daemon_flag ()) {
        int fd;

        close (STDOUT_FILENO);

        fd = open ("/var/log/rcd/rcd-messages",
                   O_WRONLY | O_CREAT | O_APPEND,
                   S_IRUSR | S_IWUSR);
        g_assert (fd == STDOUT_FILENO);
        
        close (STDERR_FILENO);
        
        fd = dup (fd); /* dup fd to stderr */
        g_assert (fd == STDERR_FILENO);
    }

    rcd_log_reinit ();

    g_idle_add (rehash_data, NULL);
} /* sighup_handler */

static void
crash_handler (int sig_num)
{
    struct sigaction sig_action;
    char cmd[128];

    sig_action.sa_handler = SIG_DFL;
    sigemptyset (&sig_action.sa_mask);
    sig_action.sa_flags = 0;

    /* Restore the default signal handlers. */
    sigaction (SIGSEGV, &sig_action, NULL);
    sigaction (SIGFPE, &sig_action, NULL);
    sigaction (SIGBUS, &sig_action, NULL);

    write (2, "Crash!\n", 7);
    
    /* FIXME: Just to be sure, we should drop privileges before doing
       this. */
    sprintf (cmd, "python " SHAREDIR "/rcd-buddy %s %d",
             rcd_executable_name, (int) getpid ());
    system (cmd);
    
    exit (1);
}

int
main (int argc, const char **argv)
{
    GMainLoop *main_loop;
    struct sigaction sig_action;
    const char *config_file;
    char *python_path;

    g_type_init ();

    rcd_executable_name = g_strdup (argv[0]);

    main_loop = g_main_loop_new (NULL, TRUE);
    rcd_shutdown_add_handler ((RCDShutdownFn) g_main_loop_quit,
                              main_loop);

    rcd_options_parse (argc, argv);

    if (rcd_options_get_show_version ()) {
        g_print ("%s\n", rcd_about_name ());
        g_print ("%s\n\n", rcd_about_copyright ());
        exit (0);
    }

    config_file = rcd_options_get_config_file ();
    if (config_file && !g_file_test (config_file, G_FILE_TEST_EXISTS)) {
        g_printerr ("Unable to find config file '%s'\n", config_file);
        g_printerr ("rcd aborting\n");

        exit (-1);
    }

    root_check ();
    if (!rcd_options_get_late_background ())
        daemonize ();

    /* Set up SIGTERM and SIGQUIT handlers */
    sig_action.sa_handler = signal_handler;
    sigemptyset (&sig_action.sa_mask);
    sig_action.sa_flags = 0;
    sigaction (SIGINT,  &sig_action, NULL);
    sigaction (SIGTERM, &sig_action, NULL);
    sigaction (SIGQUIT, &sig_action, NULL);

    /* Set up SIGHUP handler. */
    sig_action.sa_handler = sighup_handler;
    sigemptyset (&sig_action.sa_mask);
    sig_action.sa_flags = 0;
    sigaction (SIGHUP, &sig_action, NULL);
    
    /* If it looks like rcd-buddy is in the right place, set up
       handlers for crashes */
    python_path = g_find_program_in_path ("python");
    if (python_path != NULL
        && g_file_test (SHAREDIR "/rcd-buddy", G_FILE_TEST_EXISTS)) {
        sig_action.sa_handler = crash_handler;
        sigaction (SIGSEGV, &sig_action, NULL);
        sigaction (SIGFPE,  &sig_action, NULL);
        sigaction (SIGBUS,  &sig_action, NULL);
    }
    g_free (python_path);

    rcd_privileges_init ();

    initialize_logging ();

    /* Check to see if the password file is secure.
       If it isn't, a big warning will go out to the log file. */
    rcd_identity_password_file_is_secure ();

    /* Set the GPG keyring for package verification */
    rc_verification_set_keyring (SHAREDIR "/rcd.gpg");

    /* Set up the CA verification dir if we're requiring it */
    if (rcd_prefs_get_require_verified_certificates ())
        soup_set_ssl_ca_file (SHAREDIR "/rcd-ca-bundle.pem");

    /* Create mid and secret */
    if (!g_file_test (SYSCONFDIR "/mcookie", G_FILE_TEST_EXISTS))
        rcd_create_uuid (SYSCONFDIR "/mcookie");

    if (!g_file_test (SYSCONFDIR "/partnernet", G_FILE_TEST_EXISTS))
        rcd_create_uuid (SYSCONFDIR "/partnernet");
    

    initialize_rc_packman ();
    initialize_rc_services ();
    initialize_rc_world ();
    initialize_rpc ();

    if (!rcd_options_get_no_modules_flag ())
        rcd_module_init ();

    /* We can't daemonize any later than this, so hopefully module
       initialization won't be slow. */
    if (rcd_options_get_late_background ()) {
        
        rc_debug (RC_DEBUG_LEVEL_ALWAYS, "Running daemon in background.");
        daemonize ();

        /* We need to reinit logging, since the file descriptor gets closed
           when we daemonize. */
        rcd_log_reinit ();

        /* Say hello again, so it gets stored in the log file. */
        hello ();
    }

    rcd_rpc_local_server_start ();

    if (rcd_prefs_get_remote_server_enabled ()) {
        if (!rcd_rpc_remote_server_start ())
            exit (-1);
    }

    initialize_data ();
    
    /* No heartbeat if we have initialized from a dump file. */
    if (rcd_options_get_dump_file () == NULL)
        rcd_heartbeat_start ();

    g_main_run (main_loop);

    rc_debug (RC_DEBUG_LEVEL_ALWAYS, "Exited out of main loop");

    return 0;
} /* main */
