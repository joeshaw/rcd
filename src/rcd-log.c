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

    g_free (str);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static void
cutoff_time_init (RCDQueryPart *part)
{
    long x = atol (part->query_str);
    time_t *t = g_new0 (time_t, 1); 
    *t = (time_t) x;
    part->data = t;
}

static void
cutoff_time_finalize (RCDQueryPart *part)
{
    g_free (part->data);
}

static gboolean
cutoff_time_match (RCDQueryPart *part,
                   gpointer      data)
{
    RCDLogEntry *entry = data;
    time_t t = *(time_t *)part->data;
    return rcd_query_type_int_compare (part->type,
                                       (int) entry->timestamp, (int) t);
}

static gboolean
package_name_match (RCDQueryPart *part,
                    gpointer      data)
{
    gboolean x1 = FALSE, x2 = FALSE;

    RCDLogEntry *entry = data;

    if (entry->pkg_initial.name)
        x1 = rcd_query_match_string (part, entry->pkg_initial.name);

    if (!x1 && entry->pkg_final.name)
        x2 = rcd_query_match_string (part, entry->pkg_final.name);

    return x1 || x2;
}

static gboolean
action_match (RCDQueryPart *part,
              gpointer      data)
{
    RCDLogEntry *entry = data;
    return rcd_query_match_string (part, entry->action);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static RCDQueryEngine query_log_engine[] = {
    { "cutoff_time",
      NULL, cutoff_time_init, cutoff_time_finalize,
      cutoff_time_match },

    { "name",
      NULL, NULL, NULL,
      package_name_match },

    { "action",
      NULL, NULL, NULL,
      action_match },

    { NULL, NULL, NULL, NULL, NULL }
};

struct ScanInfo {
    RCDQueryPart *query_parts;
    RCDLogEntryFn entry_fn;
    gpointer      user_data;
    time_t        cutoff;
    gboolean      cutoff_hit;
};

static void
log_scan_cb (RCDLogEntry *entry, gpointer user_data)
{
    struct ScanInfo *info = user_data;
    gboolean cutoff_check;

    if (info->cutoff == 0 || difftime (info->cutoff, entry->timestamp) <= 0) {

        info->cutoff_hit = TRUE;
            
        if (rcd_query_match (info->query_parts, query_log_engine, entry)) {
            info->entry_fn (entry, info->user_data);
        }
    }
}

static gboolean
rcd_log_scan (const char   *filename,
              time_t        cutoff,
              RCDQueryPart *query_parts,
              RCDLogEntryFn entry_fn,
              gpointer      user_data)
{
    struct ScanInfo info;
    FILE *in;
    char buffer[1024];

    g_return_val_if_fail (filename && *filename, FALSE);

    if (! g_file_test (filename, G_FILE_TEST_EXISTS))
        return FALSE;

    info.query_parts = query_parts;
    info.entry_fn    = entry_fn;
    info.user_data   = user_data;
    info.cutoff      = cutoff;
    info.cutoff_hit  = FALSE;
    
    in = fopen (filename, "r");
    g_return_val_if_fail (in != NULL, FALSE);

    while (fgets (buffer, 1024, in)) {
        rcd_log_entry_parse (buffer, log_scan_cb, &info);
    }

    fclose (in);

    /* If nothing in the file is without our cutoff range, 
       return FALSE: this means we should stop walking backwards
       through the rotated log files. */

    return info.cutoff_hit;
}

void
rcd_log_query (RCDQueryPart *query_parts,
               RCDLogEntryFn entry_fn,
               gpointer      user_data)
{
    time_t cutoff;
    int i;

    if (entry_fn == NULL) 
        return;
    g_return_if_fail (query_parts != NULL);

    if (! rcd_query_begin (query_parts, query_log_engine)) {
        g_warning ("rcd_query_begin failed");
        return;
    }

    /*** Compute our cutoff ***/

    cutoff = 0;

    /* check for other cutoffs in the query */
    for (i = 0; cutoff == 0 && query_parts[i].type != RCD_QUERY_LAST; ++i) {
        if (query_parts[i].key
            && ! g_strcasecmp (query_parts[i].key, "cutoff_time")
            && (query_parts[i].type == RCD_QUERY_GT || query_parts[i].type == RCD_QUERY_GT_EQ)) {

            time_t c = (time_t) atol (query_parts[i].query_str);
            if (cutoff == 0 || difftime (cutoff, c) > 0)
                cutoff = c;

            query_parts[i].processed = TRUE;
        }
    }

    if (cutoff == 0) {
        /* default cutoff == 30 days ago */
        time (&cutoff);
        cutoff -= 60*60*24*30;
    }

    /* scan our log file */
    if (rcd_log_scan (rcd_log_path, cutoff, query_parts, entry_fn, user_data)) {
        int rot_num = 1;
        char *rot_path = NULL;

        /* scan through our rotated log files, as long as they return TRUE */
        do {
            g_free (rot_path);
            rot_path = g_strdup_printf ("%s.%d", rcd_log_path, rot_num);
            ++rot_num;
        } while (rcd_log_scan (rot_path, cutoff, query_parts, entry_fn, user_data));
        g_free (rot_path);

    }

    rcd_query_end (query_parts, query_log_engine);
}
