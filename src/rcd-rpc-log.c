/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-rpc-log.c
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
#include "rcd-rpc-log.h"

#include <libredcarpet.h>
#include "rcd-rpc.h"
#include "rcd-rpc-util.h"
#include "rcd-log-entry.h"
#include "rcd-log.h"

xmlrpc_value *
rcd_log_entry_to_xmlrpc (RCDLogEntry *entry,
                         xmlrpc_env  *env)
{
    xmlrpc_value *value = NULL, *spec;
    char *timestr, *c;

    value = xmlrpc_struct_new (env);
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_SET_STRING (env, value,
                                  "host", entry->host);

    RCD_XMLRPC_STRUCT_SET_STRING (env, value,
                                  "user", entry->user);

    RCD_XMLRPC_STRUCT_SET_STRING (env, value,
                                  "action", entry->action);
    
    timestr = ctime (&entry->timestamp);
    for (c = timestr; *c; ++c) {
        if (*c == '\n')
            *c = '\0';
    }
    RCD_XMLRPC_STRUCT_SET_STRING (env, value,
                                  "time_str", timestr);

    RCD_XMLRPC_STRUCT_SET_INT (env, value,
                               "timestamp", entry->timestamp);

    if (entry->pkg_initial.name) {
        spec = xmlrpc_struct_new (env);
        XMLRPC_FAIL_IF_FAULT (env);

        rcd_rc_package_spec_to_xmlrpc (&entry->pkg_initial, spec, env);

        xmlrpc_struct_set_value (env, value, "pkg_initial", spec);
        XMLRPC_FAIL_IF_FAULT (env);
        
        xmlrpc_DECREF (spec);
    }

    if (entry->pkg_final.name) {
        spec = xmlrpc_struct_new (env);
        XMLRPC_FAIL_IF_FAULT (env);

        rcd_rc_package_spec_to_xmlrpc (&entry->pkg_final, spec, env);

        xmlrpc_struct_set_value (env, value, "pkg_final", spec);
        XMLRPC_FAIL_IF_FAULT (env);
        
        xmlrpc_DECREF (spec);
    }

 cleanup:
    if (env->fault_occurred) {
        if (value)
            xmlrpc_DECREF (value);
        return NULL;
    }
    
    return value;
}

struct LogQueryInfo {
    xmlrpc_value *array;
    xmlrpc_env   *env;
    gboolean      failed;
};

static void
add_log_cb (RCDLogEntry *entry, gpointer user_data)
{
    struct LogQueryInfo *info = user_data;
    xmlrpc_value *entry_value;

    if (info->failed)
        return;
    
    entry_value = rcd_log_entry_to_xmlrpc (entry, info->env);
    if (entry_value) {
        xmlrpc_array_append_item (info->env, info->array, entry_value);
        xmlrpc_DECREF (entry_value);
        return;
    }

    /* fall through */
    info->failed = TRUE;
}

static xmlrpc_value *
log_query_log (xmlrpc_env   *env,
               xmlrpc_value *param_array,
               void         *user_data)
{
    struct LogQueryInfo info;
    xmlrpc_value *value;
    int size = 0, i;
    RCDQueryPart *parts = NULL;


    xmlrpc_parse_value (env, param_array, "(V)", &value);
    XMLRPC_FAIL_IF_FAULT (env);

    size = xmlrpc_array_size (env, value);
    XMLRPC_FAIL_IF_FAULT (env);

    parts = g_new0 (RCDQueryPart, size + 1);
    for (i = 0; i < size; ++i) {
        xmlrpc_value *v;

        v = xmlrpc_array_get_item (env, value, i);
        XMLRPC_FAIL_IF_FAULT (env);

        parts[i] = rcd_xmlrpc_tuple_to_query_part (v, env);
        XMLRPC_FAIL_IF_FAULT (env);

        if (parts[i].type == RCD_QUERY_INVALID) {
            xmlrpc_env_set_fault (env, RCD_RPC_FAULT_INVALID_SEARCH_TYPE,
                                  "Invalid search type");
            goto cleanup;
        }
    }

    parts[i].type = RCD_QUERY_LAST;

    info.env    = env;
    info.array  = xmlrpc_build_value (env, "()");
    info.failed = FALSE;

    rcd_log_query (parts, add_log_cb, &info);

 cleanup:
    g_free (parts);

    if (info.failed || env->fault_occurred)
        return NULL;

    return info.array;

}

void
rcd_rpc_log_register_methods (void)
{
    rcd_rpc_register_method("rcd.log.query_log",
                            log_query_log,
                            "view",
                            NULL);
}
