/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-heartbeatrtbeat.c
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
#include "rcd-heartbeat.h"

#include <time.h>

#include <rc-debug.h>

#include "rcd-prefs.h"
#include "rcd-recurring.h"

typedef struct {
    RCDHeartbeatFunc func;
    gpointer user_data;
} RCDHeartbeatFuncInfo;

/* List of RCDHearbeatFuncInfos */
static GSList *registered_heartbeat_funcs = NULL;
static RCDRecurring recurring_heartbeat;

static void
heartbeat_execute (RCDRecurring *recurring)
{
    GSList *iter;
    time_t t;

    t = time (NULL);
    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Running heartbeat at %s",
              ctime (&t));

    for (iter = registered_heartbeat_funcs; iter; iter = iter->next) {
        RCDHeartbeatFuncInfo *func_info = (RCDHeartbeatFuncInfo *) iter->data;

        (*func_info->func) (func_info->user_data);
    }
}

static time_t
heartbeat_first (RCDRecurring *recurring,
                 time_t        now)
{
    return now + rcd_prefs_get_heartbeat_interval ();
}

static time_t
heartbeat_next (RCDRecurring *recurring,
                time_t        previous)
{
    return previous + rcd_prefs_get_heartbeat_interval ();
}

void
rcd_heartbeat_start (void)
{
    if (!rcd_prefs_get_heartbeat_interval ()) {
        rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Heartbeat disabled");
        return;
    }

    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Starting heartbeat");

    recurring_heartbeat.tag     = g_quark_from_static_string ("heartbeat");
    recurring_heartbeat.execute = heartbeat_execute;
    recurring_heartbeat.first   = heartbeat_first;
    recurring_heartbeat.next    = heartbeat_next;

    rcd_recurring_add (&recurring_heartbeat);
} /* rcd_heartbeat_start */

void
rcd_heartbeat_stop (void)
{
    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Stopping heartbeat");

    rcd_recurring_remove (&recurring_heartbeat);
} /* rcd_heartbeat_stop */

void
rcd_heartbeat_register_func (RCDHeartbeatFunc func, gpointer user_data)
{
    RCDHeartbeatFuncInfo *func_info;

    g_return_if_fail (func);

    func_info = g_new0 (RCDHeartbeatFuncInfo, 1);
    func_info->func = func;
    func_info->user_data = user_data;

    registered_heartbeat_funcs = g_slist_append (
        registered_heartbeat_funcs, func_info);
} /* rcd_heartbeat_register_func */
