/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-options.c
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
#include <stdlib.h>
#include <unistd.h>

#include <popt.h>

#include "rcd-options.h"

#ifndef POPT_TABLEEND
#  define POPT_TABLEEND { NULL, '\0', 0, 0, 0, NULL, NULL }
#endif

static const char **rcd_argv = NULL;

/* global variables related to option parsing */
static char *config_file = NULL;
static gboolean non_daemon_flag = FALSE;
static gboolean download_distro_flag = FALSE;
static gboolean late_background = FALSE;
static gboolean non_root_flag = FALSE;
static gboolean no_network_flag = FALSE;
static gboolean no_modules_flag = FALSE;
static gboolean no_services_flag = FALSE;
static char *bind_ipaddress = NULL;
static gboolean remote_disable_flag = FALSE;
static int server_port = 0;
static int debug_level = -1;
static int syslog_level = -1;
static char *dump_file = NULL;
static gboolean show_version = FALSE;

void
rcd_options_parse (int argc, const char **argv)
{
    const struct poptOption command_line_options[] = {
        POPT_AUTOHELP

        { "config", 'f', POPT_ARG_STRING, &config_file, 0,
          "Specify an alternate config file to read.", "config file" },

        { "non-daemon", 'n', POPT_ARG_NONE, &non_daemon_flag, 0,
          "Don't run the daemon in the background.", NULL },

#if 0
        /* This doesn't work right now, let's not even offer it */
        { "late-background", '\0', POPT_ARG_NONE, &late_background, 0,
          "Run the daemon in the background, but not until it is ready "
          "to accept connections.", NULL },
#endif

        { "download-distro", 'o', POPT_ARG_NONE, &download_distro_flag, 0,
          "Download updated distribution information from the server", NULL },

        { "allow-non-root", '\0', POPT_ARG_NONE, &non_root_flag, 0,
          "Allow the daemon to be run as a user other than root.", NULL },

        { "no-network", '\0', POPT_ARG_NONE, &no_network_flag, 0,
          "Do not download any data from a server.", NULL },

        { "no-modules", 'm', POPT_ARG_NONE, &no_modules_flag, 0,
          "Do not load any plugin modules.", NULL },

        { "no-services", '\0', POPT_ARG_NONE, &no_services_flag, 0,
          "Do not load or save services.", NULL },

        { "ipaddress", 'i', POPT_ARG_STRING, &bind_ipaddress, 0,
          "Bind the remote server only to this IP address.", "ip address" },

        { "no-remote", 'r', POPT_ARG_NONE, &remote_disable_flag, 0,
          "Don't listen for remote connections", NULL },

        { "port", 'p', POPT_ARG_INT, &server_port, 0,
          "Listen for remote connections on a different port", NULL },

        { "debug", 'd', POPT_ARG_INT, &debug_level, 0,
          "Set the verbosity of debugging output.", "0-6" },

        { "syslog", 's', POPT_ARG_INT, &syslog_level, 0,
          "Set the verbosity of syslog output.", "0-6" },

        { "undump", '\0', POPT_ARG_STRING, &dump_file, 0,
          "Initialize daemon from a dump file.", "filename" },

        { "version", '\0', POPT_ARG_NONE, &show_version, 0,
          "Show version information", NULL },

        { NULL, '\0', 0, 0, 0, NULL, NULL }
    };

    poptContext popt_context;
    int rv;

    rcd_argv = argv;

    popt_context = poptGetContext ("rcd",
                                   argc, argv,
                                   command_line_options, 0);
    while ( (rv = poptGetNextOpt (popt_context)) > 0);

    if (rv < -1) {
        g_printerr ("%s: %s\n",
                    poptBadOption(popt_context, 0), 
                    poptStrerror (rv));
        g_printerr ("rcd aborting\n");
        exit (-1);
    }

    if (getenv ("RCD_NON_DAEMON"))
        non_daemon_flag = TRUE;
}

const char **
rcd_options_get_argv (void)
{
    return rcd_argv;
}

const char *
rcd_options_get_config_file (void)
{
    if (config_file != NULL && !g_path_is_absolute (config_file)) {
        char cwd[PATH_MAX];
        char *new_config_file;

        getcwd (cwd, PATH_MAX);

        new_config_file = g_strconcat (cwd, "/", config_file, NULL);

        g_free (config_file);
        config_file = new_config_file;
    }

    return config_file;
}

gboolean
rcd_options_get_non_daemon_flag (void)
{
    return non_daemon_flag;
}

gboolean
rcd_options_get_download_distro_flag (void)
{
    return download_distro_flag;
}

gboolean
rcd_options_get_late_background (void)
{
    return late_background;
}

gboolean
rcd_options_get_non_root_flag (void)
{
    return non_root_flag;
}

gboolean
rcd_options_get_no_network_flag (void)
{
    return no_network_flag;
}

gboolean
rcd_options_get_no_modules_flag (void)
{
    return no_modules_flag;
}

gboolean
rcd_options_get_no_services_flag (void)
{
    return no_services_flag;
}

const char *
rcd_options_get_bind_ipaddress (void)
{
    return bind_ipaddress;
}

gboolean
rcd_options_get_remote_disable_flag (void)
{
    return remote_disable_flag;
}

int
rcd_options_get_server_port (void)
{
    return server_port;
}

int
rcd_options_get_debug_level (void)
{
    return debug_level;
}

int
rcd_options_get_syslog_level (void)
{
    return syslog_level;
}

const char *
rcd_options_get_dump_file (void)
{
    return dump_file;
}

gboolean
rcd_options_get_show_version (void)
{
    return show_version;
}

void
rcd_options_reset_bind_ipaddress (void)
{
    bind_ipaddress = NULL;
}

void
rcd_options_reset_remote_disable_flag (void)
{
    remote_disable_flag = FALSE;
}

void
rcd_options_reset_server_port (void)
{
    server_port = 0;
}

void
rcd_options_reset_debug_level (void)
{
    debug_level = -1;
}

void
rcd_options_reset_syslog_level (void)
{
    syslog_level = -1;
}

