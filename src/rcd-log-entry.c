/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-log-entry.c
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
#include "rcd-log-entry.h"

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
spec_str (RCPackageSpec *spec)
{
    char epoch_str[32] = "_";

    if (spec->name == NULL) {
        return g_strdup ("_|_|_|_");
    } 
        
    if (spec->has_epoch) {
        g_snprintf (epoch_str, 32, "%d", spec->epoch);
    }

    return g_strdup_printf ("%s|%s|%s|%s",
                            spec->name,
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
    
    pkg_initial_str = spec_str (&entry->pkg_initial);
    pkg_final_str = spec_str (&entry->pkg_final);

    str = g_strdup_printf ("%ld %s|%s|%s|" /* time, host, user */
                           "%s|"       /* action */
                           "%s|%s",    /* pkg_initial, pkg_final */
                           entry->timestamp, timestr, entry->host, entry->user,
                           entry->action,
                           pkg_initial_str, pkg_final_str);

    g_free (timestr);
    g_free (pkg_initial_str);
    g_free (pkg_final_str);

    return str;
}
