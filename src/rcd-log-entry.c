/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-log-entry.c
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
#include "rcd-log-entry.h"

#include <stdlib.h>
#include <ctype.h>

RCDLogEntry *
rcd_log_entry_new (const char *host, const char *user)
{
    RCDLogEntry *entry;

    entry = g_new0 (RCDLogEntry, 1);

    time (&entry->timestamp);
    
    entry->host = host ? g_strdup (host) : "?";
    entry->user = user ? g_strdup (user) : "?";

    return entry;
}

void
rcd_log_entry_set_install (RCDLogEntry *entry,
                           RCPackage   *pkg)
{
    g_return_if_fail (entry != NULL);
    g_return_if_fail (pkg != NULL);
    g_return_if_fail (entry->action == NULL);

    entry->action = g_strdup ("install");
    
    rc_package_spec_copy (&entry->pkg_final, &pkg->spec);
}

void
rcd_log_entry_set_remove (RCDLogEntry *entry,
                          RCPackage   *pkg)
{
    g_return_if_fail (entry != NULL);
    g_return_if_fail (pkg != NULL);
    g_return_if_fail (entry->action == NULL);

    entry->action = g_strdup ("remove");

    rc_package_spec_copy (&entry->pkg_initial, &pkg->spec);
}

void
rcd_log_entry_set_upgrade (RCDLogEntry *entry,
                           RCPackage   *old_pkg,
                           RCPackage   *new_pkg)
{
    g_return_if_fail (entry != NULL);
    g_return_if_fail (entry->action == NULL);
    g_return_if_fail (old_pkg != NULL);
    g_return_if_fail (new_pkg != NULL);

    entry->action = g_strdup ("upgrade");

    rc_package_spec_copy (&entry->pkg_initial, &old_pkg->spec);
    rc_package_spec_copy (&entry->pkg_final,   &new_pkg->spec);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

RCDLogEntry *
rcd_log_entry_copy (RCDLogEntry *entry)
{
    RCDLogEntry *new_entry;

    g_return_val_if_fail (entry != NULL, NULL);

    new_entry = g_new0 (RCDLogEntry, 1);

    new_entry->timestamp = entry->timestamp;
    new_entry->user      = g_strdup (entry->user);
    new_entry->host      = g_strdup (entry->host);
    new_entry->action    = g_strdup (entry->action);
    
    rc_package_spec_copy (&new_entry->pkg_initial, &entry->pkg_initial);
    rc_package_spec_copy (&new_entry->pkg_final,   &entry->pkg_final);

    return new_entry;
}

void
rcd_log_entry_free (RCDLogEntry *entry)
{
    if (entry != NULL) {
        g_free (entry->user);
        g_free (entry->host);
        g_free (entry->action);
        rc_package_spec_free_members (&entry->pkg_initial);
        rc_package_spec_free_members (&entry->pkg_final);
        g_free (entry);
    }
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static char *
spec_to_str (RCPackageSpec *spec)
{
    char epoch_str[32] = "_";

    if (spec->nameq == 0) {
        return g_strdup ("_|_|_|_");
    } 
        
    if (spec->has_epoch) {
        g_snprintf (epoch_str, 32, "%d", spec->epoch);
    }

    return g_strdup_printf ("%s|%s|%s|%s",
                            g_quark_to_string (spec->nameq),
                            epoch_str,
                            spec->version ? spec->version : "_",
                            spec->release ? spec->release : "_");
}

char *
rcd_log_entry_to_str (RCDLogEntry *entry)
{
    char *timestr, *c, *str;
    char *pkg_initial_str;
    char *pkg_final_str;
    
    g_return_val_if_fail (entry != NULL, 0);
    
    timestr = g_strdup (ctime (&entry->timestamp));
    c = timestr;
    while (*c) {
        if (*c == '\n')
            *c = '\0';
        ++c;
    }
    
    pkg_initial_str = spec_to_str (&entry->pkg_initial);
    pkg_final_str = spec_to_str (&entry->pkg_final);

    str = g_strdup_printf ("%s |%lx|"  /* timestring, timestamp */
                           "%s|%s|"    /* host, user */
                           "%s|"       /* action */
                           "%s|%s",    /* pkg_initial, pkg_final */
                           timestr, entry->timestamp,
                           entry->host, entry->user,
                           entry->action,
                           pkg_initial_str, pkg_final_str);

    g_free (timestr);
    g_free (pkg_initial_str);
    g_free (pkg_final_str);

    return str;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static int
split_on_vbar (char *buffer, char **bufv, int bufv_len)
{
    int bv;
    char *c = buffer, *bk;

    if (buffer == NULL || bufv == NULL || bufv_len == 0)
        return 0;

    bufv[0] = buffer;
    bv = 1;

    while (*c && bv < bufv_len) {

        while (*c && *c != '|') {
            if (*c == '\n')
                *c = '\0';
            else
                ++c;
        }

        if (*c) {

            /* trim off | and trailing spaces */
            bk = c;
            while (buffer <= bk && (*bk == '|' || isspace (*bk))) {
                *bk = '\0';
                --bk;
            }

            ++c;
            /* move past leading spaces */
            while (*c && isspace (*c))
                ++c;

            bufv[bv] = c;
            ++bv;
        }
    }
    
    return bv;
}

#define IS_VBAR(s) ((s) && *(s) == '_' && *((s)+1) == '\0')
static void
spec_from_str (RCPackageSpec *spec,
               const char *name_str,
               const char *epoch_str,
               const char *version_str,
               const char *release_str)
{
    if (IS_VBAR (name_str)) {
        memset (spec, 0, sizeof (RCPackageSpec));
        return;
    }

    spec->nameq = g_quark_from_string (name_str);

    if (IS_VBAR (epoch_str)) {
        spec->has_epoch = FALSE;
        spec->epoch = 0;
    } else {
        spec->has_epoch = TRUE;
        spec->epoch = atoi (epoch_str);
    }

    spec->version = IS_VBAR (version_str) ? NULL : (char *) version_str;
    spec->release = IS_VBAR (release_str) ? NULL : (char *) release_str;
}


void
rcd_log_entry_parse (char         *buffer,
                     RCDLogEntryFn fn,
                     gpointer      user_data)
{
    RCDLogEntry entry;
    char *bufv[32];
    int N;
    
    if (fn == NULL)
        return;
    g_return_if_fail (buffer != NULL);

    N = split_on_vbar (buffer, bufv, 32);

    /* If a log line looks malformed, skip it. */
    if (N != 13)
        return;

    /* We build up our RCDLogEntry item out of the parsed chunks of
       the buffer.  This way we don't need to alloc or free any memory
       or dup any strings.  This is evil, but much more efficient. */

    entry.timestamp = (time_t) strtol (bufv[1], NULL, 16);
    entry.host      = bufv[2];
    entry.user      = bufv[3];
    entry.action    = bufv[4];

    spec_from_str (&entry.pkg_initial,
                   bufv[5], bufv[6], bufv[7], bufv[8]);

    spec_from_str (&entry.pkg_final,
                   bufv[9], bufv[10], bufv[11], bufv[12]);

    fn (&entry, user_data);
}
