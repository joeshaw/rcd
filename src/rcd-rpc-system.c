/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-rpc-system.c
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
#include "rcd-rpc-system.h"

#include <unistd.h>

#include <xmlrpc.h>

#include "rcd-about.h"
#include "rcd-cache.h"
#include "rcd-fetch.h"
#include "rcd-module.h"
#include "rcd-prefs.h"
#include "rcd-recurring.h"
#include "rcd-services.h"
#include "rcd-shutdown.h"
#include "rcd-rpc.h"
#include "rcd-rpc-util.h"
#include "rcd-xmlrpc.h"

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

    RCD_XMLRPC_STRUCT_SET_INT(env, value, "major_version", MAJOR_VERSION);
    RCD_XMLRPC_STRUCT_SET_INT(env, value, "minor_version", MINOR_VERSION);
    RCD_XMLRPC_STRUCT_SET_INT(env, value, "micro_version", MICRO_VERSION);

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
    int required_major, required_minor;
    xmlrpc_value *result;

    xmlrpc_parse_value(env, param_array, "(sii)",
                       &module_name, &required_major, &required_minor);

    if (env->fault_occurred)
        return NULL;

    module_present = rcd_module_query (module_name,
                                       required_major,
                                       required_minor);

    result = xmlrpc_build_value(env, "b", module_present);
    if (env->fault_occurred)
        return NULL;

    return result;
} /* system_query_module */

static xmlrpc_value *
rc_pending_messages_to_xmlrpc (xmlrpc_env *env, GSList *messages)
{
    xmlrpc_value *xmlrpc_msgs;
    GSList *iter;

    xmlrpc_msgs = xmlrpc_build_value (env, "()");
    XMLRPC_FAIL_IF_FAULT (env);

    for (iter = messages; iter; iter = iter->next) {
        xmlrpc_value *v;

        v = xmlrpc_build_value (env, "s", (const char *) iter->data);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_array_append_item (env, xmlrpc_msgs, v);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_DECREF (v);
    }

cleanup:
    return xmlrpc_msgs;
} /* rc_pending_messages_to_xmlrpc */

static xmlrpc_value *
system_poll_pending(xmlrpc_env   *env,
                    xmlrpc_value *param_array,
                    void         *user_data)
{
    xmlrpc_value *value = NULL;
    gint pending_id;
    RCPending *pending;

    xmlrpc_parse_value (env, param_array, "(i)", &pending_id);
    if (env->fault_occurred)
        return NULL;

    pending = rc_pending_lookup_by_id (pending_id);
    
    value = xmlrpc_struct_new (env);

    if (pending != NULL) {
        xmlrpc_value *messages;

        RCD_XMLRPC_STRUCT_SET_INT (env, value, "id",
                                   rc_pending_get_id (pending));

        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "description",
                                      rc_pending_get_description (pending));

        RCD_XMLRPC_STRUCT_SET_DOUBLE (env, value, "percent_complete",
                                      rc_pending_get_percent_complete (pending));

        if (rc_pending_get_completed_size (pending) >= 0) {
            RCD_XMLRPC_STRUCT_SET_INT (env, value, "completed_size",
                                       rc_pending_get_completed_size (pending));
        }

        if (rc_pending_get_total_size (pending) >= 0) {
            RCD_XMLRPC_STRUCT_SET_INT (env, value, "total_size",
                                       rc_pending_get_total_size (pending));
        }

        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "status",
                                      rc_pending_status_to_string (rc_pending_get_status (pending)));
        
        RCD_XMLRPC_STRUCT_SET_INT (env, value, "is_active",
                                   rc_pending_is_active (pending) ? 1 : 0);

        if (rc_pending_get_elapsed_secs (pending) >= 0) {
            RCD_XMLRPC_STRUCT_SET_INT (env, value, "elapsed_sec",
                                       rc_pending_get_elapsed_secs (pending));
        }
     
        if (rc_pending_get_remaining_secs (pending) >= 0) {
            RCD_XMLRPC_STRUCT_SET_INT (env, value, "remaining_sec",
                                       rc_pending_get_remaining_secs (pending));
        }


        if (rc_pending_get_expected_secs (pending) >= 0) {
            RCD_XMLRPC_STRUCT_SET_INT (env, value, "expected_sec",
                                       rc_pending_get_expected_secs (pending));
        }

        if (rc_pending_get_start_time (pending)) {
            RCD_XMLRPC_STRUCT_SET_INT (env, value, "start_time",
                                       (gint) rc_pending_get_start_time (pending));
        }

        if (rc_pending_get_last_time (pending)) {
            RCD_XMLRPC_STRUCT_SET_INT (env, value, "last_time",
                                       (gint) rc_pending_get_last_time (pending));
        }

        if (rc_pending_get_error_msg (pending)) {
            RCD_XMLRPC_STRUCT_SET_STRING (env, value, "error_msg",
                                          rc_pending_get_error_msg (pending));
        }

        messages = rc_pending_messages_to_xmlrpc (
            env, rc_pending_get_messages (pending));
        XMLRPC_FAIL_IF_FAULT (env);
        
        xmlrpc_struct_set_value (env, value, "messages", messages);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_DECREF (messages);
    }

 cleanup: 
    if (env->fault_occurred) {
        if (value)
            xmlrpc_DECREF(value);
        return NULL;
    }

    return value;
}

static xmlrpc_value *
system_get_all_pending (xmlrpc_env   *env,
                        xmlrpc_value *param_array,
                        void         *user_data)
{
    xmlrpc_value *value;
    GSList *id_list, *iter;

    id_list = rc_pending_get_all_active_ids ();

    value = xmlrpc_build_value (env, "()");
    if (env->fault_occurred)
        goto cleanup;

    for (iter = id_list; iter != NULL; iter = iter->next) {
        gint id;
        xmlrpc_value *id_value;

        id = GPOINTER_TO_INT (iter->data);

        id_value = xmlrpc_build_value (env, "i", id);
        if (env->fault_occurred)
            goto cleanup;

        xmlrpc_array_append_item (env, value, id_value);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_DECREF (id_value);
    }

 cleanup:
    g_slist_free (id_list);

    if (env->fault_occurred) {
        xmlrpc_DECREF (value);
        return NULL;
    }

    return value;
}

static xmlrpc_value *
system_shutdown (xmlrpc_env   *env,
                 xmlrpc_value *param_array,
                 void         *user_data)
{
    rcd_shutdown ();
    return xmlrpc_build_value (env, "i", 1);
}

static xmlrpc_value *
system_restart (xmlrpc_env   *env,
                xmlrpc_value *param_array,
                void         *user_data)
{
    rcd_restart ();
    return xmlrpc_build_value (env, "i", 1);
}

static xmlrpc_value *
system_activate (xmlrpc_env   *env,
                 xmlrpc_value *param_array,
                 void         *user_data)
{
    char *activation_code, *email;
    char *alias = NULL;
    int param_count;
    xmlrpc_value *value = NULL;

    param_count = xmlrpc_array_size (env, param_array);
    XMLRPC_FAIL_IF_FAULT (env);

    if (param_count == 2)
        xmlrpc_parse_value (env, param_array, "(ss)", &activation_code, &email);
    else
        xmlrpc_parse_value (env, param_array, "(sss)",
                            &activation_code, &email, &alias);
    XMLRPC_FAIL_IF_FAULT (env);

    value = rcd_fetch_register (env, activation_code, email, alias);
    XMLRPC_FAIL_IF_FAULT (env);

cleanup:

    return value;
}

struct RecurringInfo {
    xmlrpc_env *env;
    xmlrpc_value *array;
};

static void
get_recurring_cb (RCDRecurring *rec,
                  gpointer      user_data)
{
    struct RecurringInfo *info = user_data;
    char *label_str;
    xmlrpc_value *item;
    time_t now;
    char buf[128];

    item = xmlrpc_struct_new (info->env);

    time (&now);

    label_str = rcd_recurring_get_label (rec);
    RCD_XMLRPC_STRUCT_SET_STRING (info->env, item, "label", label_str);
    g_free (label_str);

    RCD_XMLRPC_STRUCT_SET_INT (info->env, item, "when", rec->when);
    if (rec->when) {
        struct tm *t = localtime (&rec->when);
        strftime (buf, 128, "%b %d, %R", t);
        RCD_XMLRPC_STRUCT_SET_STRING (info->env, item, "when_str", buf);
        RCD_XMLRPC_STRUCT_SET_INT (info->env, item,
                                   "when_delta", 
                                   (int) difftime (rec->when, now));
    } else {
        RCD_XMLRPC_STRUCT_SET_STRING (info->env, item, "when_str", "now");
    }

    if (rec->prev) {
        struct tm *t = localtime (&rec->prev);
        strftime (buf, 128, "%b %d, %R", t);
        RCD_XMLRPC_STRUCT_SET_INT (info->env, item, "prev", rec->prev);
        RCD_XMLRPC_STRUCT_SET_STRING (info->env, item, "prev_str", buf);
        RCD_XMLRPC_STRUCT_SET_INT (info->env, item,
                                   "prev_delta",
                                   (int) difftime (now, rec->prev));
    }

    RCD_XMLRPC_STRUCT_SET_INT (info->env, item, "count", rec->count);

    xmlrpc_array_append_item (info->env, info->array, item);

 cleanup:
    ;
}

static xmlrpc_value *
system_get_recurring (xmlrpc_env   *env,
                      xmlrpc_value *param_array,
                      void         *user_data)
{
    struct RecurringInfo info;

    info.env = env;
    info.array = xmlrpc_build_value (env, "()");

    /* FIXME: we need error checking here */

    rcd_recurring_foreach (0, get_recurring_cb, &info);

    return info.array;
}

static xmlrpc_value *
system_get_cache_size (xmlrpc_env   *env,
                       xmlrpc_value *param_array,
                       void         *user_data)
{
    return xmlrpc_build_value (env, "i",
                               rcd_cache_size (rcd_cache_get_package_cache ()));
}

static xmlrpc_value *
system_flush_cache (xmlrpc_env   *env,
                    xmlrpc_value *param_array,
                    void         *user_data)
{
    rcd_cache_expire_now (rcd_cache_get_package_cache ());

    return xmlrpc_build_value (env, "i", 0);
}

typedef struct {
    xmlrpc_env *env;
    xmlrpc_value *result;
} ServiceInfo;

static gboolean
add_service_cb (RCWorld *subworld, gpointer user_data)
{
    RCWorldService *service = RC_WORLD_SERVICE (subworld);
    ServiceInfo *info = user_data;
    xmlrpc_value *xmlrpc_service;

    xmlrpc_service = xmlrpc_struct_new (info->env);
    XMLRPC_FAIL_IF_FAULT (info->env);

    RCD_XMLRPC_STRUCT_SET_STRING (info->env, xmlrpc_service,
                                  "url", service->url);

    if (service->name) {
        RCD_XMLRPC_STRUCT_SET_STRING (info->env, xmlrpc_service,
                                      "name", service->name);
    }

    if (service->unique_id) {
        RCD_XMLRPC_STRUCT_SET_STRING (info->env, xmlrpc_service,
                                      "id", service->unique_id);
    }

    RCD_XMLRPC_STRUCT_SET_INT (info->env, xmlrpc_service,
                               "is_sticky", service->is_sticky);

    RCD_XMLRPC_STRUCT_SET_INT (info->env, xmlrpc_service,
                               "is_invisible", service->is_invisible);

    RCD_XMLRPC_STRUCT_SET_INT (info->env, xmlrpc_service,
                               "is_singleton", service->is_singleton);

    xmlrpc_array_append_item (info->env, info->result, xmlrpc_service);
    XMLRPC_FAIL_IF_FAULT (info->env);

    xmlrpc_DECREF (xmlrpc_service);

cleanup:
    if (info->env->fault_occurred)
        return FALSE;

    return TRUE;
}

static xmlrpc_value *
system_list_services (xmlrpc_env   *env,
                      xmlrpc_value *param_array,
                      void         *user_data)
{
    ServiceInfo info;

    info.result = xmlrpc_build_value (env, "()");
    XMLRPC_FAIL_IF_FAULT (env);

    info.env = env;

    rc_world_multi_foreach_subworld_by_type (RC_WORLD_MULTI (rc_get_world ()),
                                             RC_TYPE_WORLD_SERVICE,
                                             add_service_cb,
                                             &info);
    XMLRPC_FAIL_IF_FAULT (env);

cleanup:
    if (env->fault_occurred) {
        xmlrpc_DECREF (info.result);
        return NULL;
    } else
        return info.result;
}

static xmlrpc_value *
system_add_service (xmlrpc_env   *env,
                    xmlrpc_value *param_array,
                    void         *user_data)
{
    char *service_url;

    xmlrpc_parse_value (env, param_array, "(s)", &service_url);
    XMLRPC_FAIL_IF_FAULT (env);

    if (!rc_world_multi_mount_service (RC_WORLD_MULTI (rc_get_world ()),
                                       service_url)) {
        xmlrpc_env_set_fault_formatted (env, RCD_RPC_FAULT_INVALID_SERVICE,
                                        "Unable to mount service for '%s'",
                                        service_url);
    } else
        rcd_services_save ();

cleanup:
    if (env->fault_occurred)
        return NULL;

    return xmlrpc_build_value (env, "i", 0);
}

static xmlrpc_value *
system_remove_service (xmlrpc_env   *env,
                       xmlrpc_value *param_array,
                       void         *user_data)
{
    char *service_url;
    RCWorldService *service;

    xmlrpc_parse_value (env, param_array, "(s)", &service_url);
    XMLRPC_FAIL_IF_FAULT (env);

    service = rc_world_multi_lookup_service (RC_WORLD_MULTI (rc_get_world ()),
                                             service_url);

    if (!service) {
        xmlrpc_env_set_fault_formatted (env, RCD_RPC_FAULT_INVALID_SERVICE,
                                        "Unable to unmount service for '%s'",
                                        service_url);
        goto cleanup;
    }

    rc_world_multi_remove_subworld (RC_WORLD_MULTI (rc_get_world ()),
                                    RC_WORLD (service));

    rcd_services_save ();

cleanup:
    if (env->fault_occurred)
        return NULL;

    return xmlrpc_build_value (env, "i", 0);
}

void
rcd_rpc_system_register_methods(void)
{
    rcd_rpc_register_method ("rcd.system.ping",
                             system_ping,
                             NULL, NULL);
	rcd_rpc_register_method ("rcd.system.query_module",
                             system_query_module,
                             NULL, NULL);
	rcd_rpc_register_method ("rcd.system.poll_pending",
                             system_poll_pending,
                             NULL, NULL);
	rcd_rpc_register_method ("rcd.system.get_all_pending",
                             system_get_all_pending,
                             NULL, NULL);
	rcd_rpc_register_method ("rcd.system.shutdown",
                             system_shutdown,
                             "superuser", NULL);
	rcd_rpc_register_method ("rcd.system.restart",
                             system_restart,
                             "superuser", NULL);
    rcd_rpc_register_method ("rcd.system.activate",
                             system_activate,
                             "superuser", NULL);
    rcd_rpc_register_method ("rcd.system.get_recurring",
                             system_get_recurring,
                             NULL, NULL);
    rcd_rpc_register_method ("rcd.system.get_cache_size",
                             system_get_cache_size,
                             "view", NULL);
    rcd_rpc_register_method ("rcd.system.flush_cache",
                             system_flush_cache,
                             "superuser", NULL);
    rcd_rpc_register_method ("rcd.system.list_services",
                             system_list_services,
                             "view", NULL);
    rcd_rpc_register_method ("rcd.system.add_service",
                             system_add_service,
                             "superuser", NULL);
    rcd_rpc_register_method ("rcd.system.remove_service",
                             system_remove_service,
                             "superuser", NULL);

} /* rcd_rpc_system_register_methods */

