/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-log-entry.h
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

#ifndef __RCD_LOG_ENTRY_H__
#define __RCD_LOG_ENTRY_H__

#include <glib.h>
#include <time.h>

#include <libredcarpet.h>

typedef struct _RCDLogEntry RCDLogEntry;

typedef void (*RCDLogEntryFn) (RCDLogEntry *entry, gpointer user_data);

struct _RCDLogEntry {
    time_t timestamp;

    char *host;
    char *user;

    /* install, remove, upgrade */
    char *action;

    RCPackageSpec pkg_initial;
    RCPackageSpec pkg_final;
};

RCDLogEntry *rcd_log_entry_new (const char *host, const char *user);

void rcd_log_entry_set_install (RCDLogEntry *entry, RCPackage *pkg);
void rcd_log_entry_set_remove  (RCDLogEntry *entry, RCPackage *pkg);
void rcd_log_entry_set_upgrade (RCDLogEntry *entry, RCPackage *old_pkg, RCPackage *new_pkg);

RCDLogEntry *rcd_log_entry_copy (RCDLogEntry *entry);
void         rcd_log_entry_free (RCDLogEntry *entry);

char * rcd_log_entry_to_str (RCDLogEntry *entry);
void   rcd_log_entry_parse  (char *buffer, RCDLogEntryFn fn, gpointer user_data);

#endif /* __RCD_LOG_ENTRY_H__ */

