/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-log.c
 *
 * Copyright (C) 2002 Ximian, Inc.
 *
 * Developed by Jon Trowbridge <trow@ximian.com>
 */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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
#include "rcd-log.h"

#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define RCD_DEFAULT_LOG "/tmp/rcdlog"

static char *rcd_log_path = NULL;
static int   rcd_log_fd   = -1;

static void
rcd_open_log_file (void)
{
    g_assert (rcd_log_path != NULL);

    if (rcd_log_fd >= 0)
        close (rcd_log_fd);

    rc_debug (RC_DEBUG_LEVEL_INFO, "Opening logfile '%s'", rcd_log_path);

    rcd_log_fd = open (rcd_log_path,
                       O_WRONLY | O_CREAT | O_APPEND,
                       S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (rcd_log_path < 0) {
        rc_debug (RC_DEBUG_LEVEL_ERROR, "Can't open rcd log file '%s'", rcd_log_path);
    }
}

/* Re-open the log file on SIGHUP.  This is done to support
   log rotation. */
static void
sighup_handler (int foo)
{
    rcd_open_log_file ();
}

void
rcd_log_init (const char *log_path)
{
    struct sigaction sighup_action;

    if (rcd_log_path != NULL) {
        rc_debug (RC_DEBUG_LEVEL_WARNING, "Can't re-initialize logging.");
    }

    rcd_log_path = g_strdup (log_path ? log_path : RCD_DEFAULT_LOG);
    rcd_open_log_file ();

    sighup_action.sa_handler = sighup_handler;
    sigemptyset (&sighup_action.sa_mask);
    sighup_action.sa_flags = 0;

    sigaction (SIGHUP, &sighup_action, NULL);
}

static void
actually_write (const char *str)
{
}

void
rcd_log (RCDLogEntry *entry)
{
    char *str;

    g_return_if_fail (entry != NULL);
    g_return_if_fail (entry->action && *entry->action);

    str = rcd_log_entry_to_str (entry);
    g_return_if_fail (str != NULL);

    if (rcd_log_fd < 0) {
        rc_debug (RC_DEBUG_LEVEL_WARNING, 
                  "Log not open, can't write log message \"%s\"",
                  str);
        return;
    }

    /* FIXME should check that these writes succeed */
    write (rcd_log_fd, str, strlen (str));
    write (rcd_log_fd, "\n", 1);
}
