/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-heartbeat.c
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

typedef struct {
    RCDHeartbeatFunc func;
    gpointer user_data;
} RCDHeartbeatFuncInfo;

/* List of RCDHearbeatFuncInfos */
static GSList *registered_heartbeat_funcs = NULL;
static guint32 heartbeat_interval = 0;
static int heartbeat_id = 0;
static gboolean heartbeat_running = FALSE;

static gboolean
run_heartbeat (gpointer user_data)
{
    time_t t;
    GSList *iter;
    guint32 interval;

    if (heartbeat_running == TRUE) {
        rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Heartbeat is already running; "
                  "Suggest lowering heartbeat interval");
        return TRUE;
    }

    heartbeat_running = TRUE;

    t = time (NULL);
    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Running heartbeat at %s",
              ctime (&t));

    for (iter = registered_heartbeat_funcs; iter; iter = iter->next) {
        RCDHeartbeatFuncInfo *func_info = (RCDHeartbeatFuncInfo *) iter->data;

        (*func_info->func) (func_info->user_data);
    }

    interval = rcd_prefs_get_heartbeat_interval ();
    if (interval != heartbeat_interval) {
        heartbeat_interval = interval;
        heartbeat_id = g_timeout_add (heartbeat_interval * 1000,
                                      run_heartbeat, NULL);

        heartbeat_running = FALSE;

        return FALSE;
    }
    else {
        heartbeat_running = FALSE;

        return TRUE;
    }
} /* run_heartbeat */

void
rcd_heartbeat_start (void)
{
    g_return_if_fail (heartbeat_id == 0);

    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Starting heartbeat");

    heartbeat_interval = rcd_prefs_get_heartbeat_interval();

    heartbeat_id = g_timeout_add (heartbeat_interval * 1000,
                                  run_heartbeat, NULL);
} /* rcd_heartbeat_start */

void
rcd_heartbeat_stop (void)
{
    g_return_if_fail (heartbeat_id != 0);

    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Stopping heartbeat");

    g_source_remove (heartbeat_id);
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
