/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-rpc.c
 *
 * Copyright (C) 2002 Ximian, Inc.
 *
 */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License, version 2,
 * as published by the Free Software Foundation.
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
#include "rcd-rpc-system.h"

#include <xmlrpc.h>

#include "rcd-about.h"
#include "rcd-module.h"
#include "rcd-pending.h"
#include "rcd-rpc.h"
#include "rcd-rpc-util.h"

static xmlrpc_value *
system_ping(xmlrpc_env   *env,
            xmlrpc_value *param_array,
            void         *user_data)
{
    xmlrpc_value *value = NULL;
    time_t now;

    value = xmlrpc_struct_new(env);

    /* Add server name */

    RCD_XMLRPC_STRUCT_SET_STRING(env, value, "name", rcd_about_name ());
    XMLRPC_FAIL_IF_FAULT(env);

    RCD_XMLRPC_STRUCT_SET_STRING(env, value, "copyright", rcd_about_copyright ());
    XMLRPC_FAIL_IF_FAULT(env);

    time (&now);
    RCD_XMLRPC_STRUCT_SET_INT(env, value, "current_time", (gint) now);
    XMLRPC_FAIL_IF_FAULT(env);
    
 cleanup: 
    if (env->fault_occurred) {
        if (value)
            xmlrpc_DECREF(value);
        return NULL;
    }

    return value;
}

static xmlrpc_value *
system_query_module(xmlrpc_env   *env,
                    xmlrpc_value *param_array,
                    void         *user_data)
{
    char *module_name;
    gboolean module_present;
    xmlrpc_value *result;

    xmlrpc_parse_value(env, param_array, "(s)", &module_name);
    if (env->fault_occurred)
        return NULL;

    module_present = rcd_module_query(module_name);

    result = xmlrpc_build_value(env, "b", module_present);
    if (env->fault_occurred)
        return NULL;

    return result;
} /* system_query_module */

static xmlrpc_value *
system_poll_pending(xmlrpc_env   *env,
                    xmlrpc_value *param_array,
                    void         *user_data)
{
    xmlrpc_value *value = NULL;
    gint pending_id;
    RCDPending *pending;

    xmlrpc_parse_value (env, param_array, "(i)", &pending_id);
    if (env->fault_occurred)
        return NULL;

    pending = rcd_pending_lookup_by_id (pending_id);
    
    value = xmlrpc_struct_new (env);

    if (pending != NULL) {

        RCD_XMLRPC_STRUCT_SET_INT (env, value, "id",
                                   rcd_pending_get_id (pending));

        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "description",
                                      rcd_pending_get_description (pending));

        RCD_XMLRPC_STRUCT_SET_DOUBLE (env, value, "percent_complete",
                                      rcd_pending_get_percent_complete (pending));

        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "status",
                                      rcd_pending_status_to_string (rcd_pending_get_status (pending)));

        if (rcd_pending_get_elapsed_secs (pending) >= 0) {
            RCD_XMLRPC_STRUCT_SET_INT (env, value, "elased_sec",
                                       rcd_pending_get_elapsed_secs (pending));
        }
        
        if (rcd_pending_get_remaining_secs (pending) >= 0) {
            RCD_XMLRPC_STRUCT_SET_INT (env, value, "remaining_sec",
                                       rcd_pending_get_remaining_secs (pending));
        }

        if (rcd_pending_get_expected_secs (pending) >= 0) {
            RCD_XMLRPC_STRUCT_SET_INT (env, value, "expected_sec",
                                       rcd_pending_get_expected_secs (pending));
        }

        if (rcd_pending_get_start_time (pending)) {
            RCD_XMLRPC_STRUCT_SET_INT (env, value, "start_time",
                                       (gint) rcd_pending_get_start_time (pending));
        }

        if (rcd_pending_get_last_time (pending)) {
            RCD_XMLRPC_STRUCT_SET_INT (env, value, "last_time",
                                       (gint) rcd_pending_get_last_time (pending));
        }
    }

 cleanup: 
    if (env->fault_occurred) {
        if (value)
            xmlrpc_DECREF(value);
        return NULL;
    }

    return value;
}
	
void
rcd_rpc_system_register_methods(void)
{
    rcd_rpc_register_method(
        "rcd.system.ping", system_ping, NULL, NULL);
	rcd_rpc_register_method(
        "rcd.system.query_module", system_query_module, NULL, NULL);
	rcd_rpc_register_method(
        "rcd.system.poll_pending", system_poll_pending, NULL, NULL);
} /* rcd_rpc_system_register_methods */

