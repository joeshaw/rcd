/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-rpc-service.c
 *
 * Copyright (C) 2003 Ximian, Inc.
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

#include "rcd-heartbeat.h"
#include "rcd-rpc.h"
#include "rcd-rpc-util.h"
#include "rcd-services.h"
#include "rcd-transaction.h"
#include "rcd-world-remote.h"

static RCWorldService *
service_lookup (const char *identifier)
{
    RCWorldMulti *multi = RC_WORLD_MULTI (rc_get_world ());
    RCWorldService *service;

    service = rc_world_multi_lookup_service (multi, identifier);

    if (!service)
        service = rc_world_multi_lookup_service_by_id (multi, identifier);

    return service;
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

    if (g_type_is_a (G_TYPE_FROM_INSTANCE (service), RCD_TYPE_WORLD_REMOTE)) {
        RCDWorldRemote *remote = RCD_WORLD_REMOTE (service);

        if (remote->distro) {
            RCD_XMLRPC_STRUCT_SET_STRING (info->env, xmlrpc_service,
                                          "distro_name",
                                          rc_distro_get_name (remote->distro));

            RCD_XMLRPC_STRUCT_SET_STRING (info->env, xmlrpc_service,
                                          "distro_version",
                                          rc_distro_get_version (remote->distro));

            RCD_XMLRPC_STRUCT_SET_STRING (info->env, xmlrpc_service,
                                          "distro_target",
                                          rc_distro_get_target (remote->distro));
        }

        if (remote->contact_email) {
            RCD_XMLRPC_STRUCT_SET_STRING (info->env, xmlrpc_service,
                                          "contact_email",
                                          remote->contact_email);
        }

        RCD_XMLRPC_STRUCT_SET_INT (info->env, xmlrpc_service,
                                   "premium_service", remote->premium_service);
    }

    xmlrpc_array_append_item (info->env, info->result, xmlrpc_service);
    XMLRPC_FAIL_IF_FAULT (info->env);

    xmlrpc_DECREF (xmlrpc_service);

cleanup:
    if (info->env->fault_occurred)
        return FALSE;

    return TRUE;
}

static xmlrpc_value *
service_list (xmlrpc_env   *env,
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
service_add (xmlrpc_env   *env,
             xmlrpc_value *param_array,
             void         *user_data)
{
    char *service_url, *mangled_url;
    GError *err = NULL;

    xmlrpc_parse_value (env, param_array, "(s)", &service_url);
    XMLRPC_FAIL_IF_FAULT (env);

    /* We always want to download data from the site */
    mangled_url = g_strconcat (service_url, "?remote_only=1", NULL);

    if (!rc_world_multi_mount_service (RC_WORLD_MULTI (rc_get_world ()),
                                       mangled_url, &err)) {
        xmlrpc_env_set_fault_formatted (env, RCD_RPC_FAULT_INVALID_SERVICE,
                                        "Unable to mount service for '%s': %s",
                                        service_url, err->message);
    } else
        rcd_services_save ();

    g_free (mangled_url);

cleanup:
    if (env->fault_occurred)
        return NULL;

    return xmlrpc_build_value (env, "i", 0);
}

static xmlrpc_value *
service_remove (xmlrpc_env   *env,
                xmlrpc_value *param_array,
                void         *user_data)
{
    char *service_identifier;
    RCWorldService *service;

    xmlrpc_parse_value (env, param_array, "(s)", &service_identifier);
    XMLRPC_FAIL_IF_FAULT (env);

    service = service_lookup (service_identifier);

    if (!service) {
        xmlrpc_env_set_fault_formatted (env, RCD_RPC_FAULT_INVALID_SERVICE,
                                        "Unable to unmount service for '%s'",
                                        service_identifier);
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

static xmlrpc_value *
rcd_mirror_to_xmlrpc (RCDMirror  *mirror,
                      xmlrpc_env *env)
{
    xmlrpc_value *value;
    g_return_val_if_fail (mirror != NULL, NULL);

    value = xmlrpc_struct_new (env);
    XMLRPC_FAIL_IF_FAULT (env);

    if (mirror->name && *mirror->name)
        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "name",
                                      mirror->name);

    if (mirror->location && *mirror->location)
        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "location",
                                      mirror->location);

    if (mirror->url && *mirror->url)
        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "url",
                                      mirror->url);

    if (mirror->ftp && *mirror->ftp)
        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "ftp",
                                      mirror->ftp);

    if (mirror->contact && *mirror->contact)
        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "contact",
                                      mirror->contact);

 cleanup:
    if (env->fault_occurred) {
        if (value)
            xmlrpc_DECREF (value);
        return NULL;
    }

    return value;
}

struct GetAllInfo {
    xmlrpc_value *array;
    xmlrpc_env   *env;
    gboolean      failed;
};

static void
add_mirror_cb (RCDMirror *mirror, gpointer user_data)
{
    struct GetAllInfo *info = user_data;
    xmlrpc_value *mirror_value;

    if (info->failed)
        return;

    mirror_value = rcd_mirror_to_xmlrpc (mirror, info->env);
    if (mirror_value) {
        xmlrpc_array_append_item (info->env, info->array, mirror_value);
        xmlrpc_DECREF (mirror_value);
        return;
    }

    /* Fall through on error */
    info->failed = TRUE;
}

static xmlrpc_value *
service_get_mirrors (xmlrpc_env   *env,
                     xmlrpc_value *param_array,
                     void         *user_data)
{
    char *service_identifier;
    RCWorldMulti *multi;
    RCWorldService *service;
    struct GetAllInfo info;

    xmlrpc_parse_value (env, param_array, "(s)", &service_identifier);
    XMLRPC_FAIL_IF_FAULT (env);

    multi = RC_WORLD_MULTI (rc_get_world ());

    service = service_lookup (service_identifier);

    if (!service || !g_type_is_a (G_TYPE_FROM_INSTANCE (service),
                                  RCD_TYPE_WORLD_REMOTE))
    {
        xmlrpc_env_set_fault_formatted (env, RCD_RPC_FAULT_INVALID_SERVICE,
                                        "Unable to find service '%s'",
                                        service_identifier);
        goto cleanup;
    }

    info.env = env;
    info.array = xmlrpc_build_value (env, "()");
    info.failed = FALSE;

    rcd_world_remote_foreach_mirror (RCD_WORLD_REMOTE (service),
                                     add_mirror_cb, &info);

cleanup:
    if (env->fault_occurred)
        return NULL;

    return info.array;
}

static xmlrpc_value *
service_set_url (xmlrpc_env   *env,
                 xmlrpc_value *param_array,
                 void         *user_data)
{
    char *service_identifier;
    char *old_url, *new_url;
    RCWorldService *service;

    xmlrpc_parse_value (env, param_array, "(ss)",
                        &service_identifier, &new_url);
    XMLRPC_FAIL_IF_FAULT (env);

    service = service_lookup (service_identifier);

    if (!service) {
        xmlrpc_env_set_fault_formatted (env, RCD_RPC_FAULT_INVALID_SERVICE,
                                        "Unable to unmount service for '%s'",
                                        service_identifier);
        goto cleanup;
    }

    old_url = service->url;
    service->url = g_strdup (new_url);

    if (!rc_world_refresh (RC_WORLD (service))) {
        xmlrpc_env_set_fault_formatted (env, RCD_RPC_FAULT_INVALID_SERVICE,
                                        "Unable to change mirrors for '%s'",
                                        service->name);
        g_free (service->url);
        service->url = old_url;
        goto cleanup;
    }

    g_free (old_url);

    rcd_services_save ();

cleanup:
    if (env->fault_occurred)
        return NULL;

    return xmlrpc_build_value (env, "i", 0);
}

static xmlrpc_value *
service_refresh (xmlrpc_env   *env,
                 xmlrpc_value *param_array,
                 void         *user_data)
{
    int size;
    RCWorld *world;
    xmlrpc_value *value = NULL;
    RCPending *pending;
    char *err_msg = NULL;

    if (rcd_transaction_is_locked ()) {
        xmlrpc_env_set_fault (env, RCD_RPC_FAULT_LOCKED,
                              "Transaction lock in place");
        return NULL;
    }

    size = xmlrpc_array_size (env, param_array);
    XMLRPC_FAIL_IF_FAULT (env);

    if (size > 0) {
        char *service_identifier;

        xmlrpc_parse_value (env, param_array, "(s)", &service_identifier);
        XMLRPC_FAIL_IF_FAULT (env);

        world = RC_WORLD (service_lookup (service_identifier));

        if (!world) {
            xmlrpc_env_set_fault_formatted (env, RCD_RPC_FAULT_INVALID_SERVICE,
                                            "Unable to find service '%s'",
                                            service_identifier);
            goto cleanup;
        }
    } else {
        world = rc_get_world ();
    }

    /* FIXME: err_msg ? */
    pending = rc_world_refresh (world);

    if (err_msg) {
        xmlrpc_env_set_fault_formatted (
            env, RCD_RPC_FAULT_CANT_REFRESH,
            "Unable to download channel data: %s", err_msg);
        goto cleanup;
    }

    if (pending)
        value = xmlrpc_build_value (env, "(i)", rc_pending_get_id (pending));
    else
        value = xmlrpc_build_value (env, "()");
    XMLRPC_FAIL_IF_FAULT (env);
    
 cleanup:
    if (err_msg)
        g_free (err_msg);

    if (env->fault_occurred)
        return NULL;

    return value;
}

static xmlrpc_value *
service_refresh_blocking (xmlrpc_env   *env,
                          xmlrpc_value *param_array,
                          void         *user_data)
{
    int size;
    RCWorld *world;
    RCPending *pending;
    GSList *pending_list;
    char *err_msg = NULL;

    if (rcd_transaction_is_locked ()) {
        xmlrpc_env_set_fault (env, RCD_RPC_FAULT_LOCKED,
                              "Transaction lock in place");
        return NULL;
    }

    size = xmlrpc_array_size (env, param_array);
    XMLRPC_FAIL_IF_FAULT (env);

    if (size > 0) {
        char *service_identifier;

        xmlrpc_parse_value (env, param_array, "(s)", &service_identifier);
        XMLRPC_FAIL_IF_FAULT (env);

        world = RC_WORLD (service_lookup (service_identifier));

        if (!world) {
            xmlrpc_env_set_fault_formatted (env, RCD_RPC_FAULT_INVALID_SERVICE,
                                            "Unable to find service '%s'",
                                            service_identifier);
            goto cleanup;
        }
    } else {
        world = rc_get_world ();
    }

    /* FIXME: err_msg ? */
    pending = rc_world_refresh (world);

    if (err_msg) {
        xmlrpc_env_set_fault_formatted (
            env, RCD_RPC_FAULT_CANT_REFRESH,
            "Unable to download channel data: %s", err_msg);
        goto cleanup;
    }
    
    pending_list = g_slist_prepend (NULL, pending);
    rcd_rpc_block_on_pending_list (env, pending_list, FALSE,
                                   RCD_RPC_FAULT_CANT_REFRESH);
    g_slist_free (pending_list);
    
cleanup:
    if (err_msg)
        g_free (err_msg);

    if (env->fault_occurred)
        return NULL;

    return xmlrpc_build_value (env, "i", 0);
}

static gboolean
get_singleton_remote_cb (RCWorld *world, gpointer user_data)
{
    RCDWorldRemote **remote = user_data;

    /* There's more than one remote */
    if (*remote != NULL)
        return FALSE;

    *remote = RCD_WORLD_REMOTE (world);

    return TRUE;
}

static xmlrpc_value *
service_activate (xmlrpc_env   *env,
                  xmlrpc_value *param_array,
                  void         *user_data)
{
    xmlrpc_value *activation_info;
    char *activation_code;
    char *email = NULL, *service_identifier = NULL, *alias = NULL;
    RCWorldService *service;
    char *err_msg;

    xmlrpc_parse_value (env, param_array, "(V)", &activation_info);
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_GET_STRING (env, activation_info,
                                  "activation_code", activation_code);

    if (xmlrpc_struct_has_key (env, activation_info, "email")) {
        RCD_XMLRPC_STRUCT_GET_STRING (env, activation_info,
                                      "email", email);
    }

    if (xmlrpc_struct_has_key (env, activation_info, "alias")) {
        RCD_XMLRPC_STRUCT_GET_STRING (env, activation_info,
                                      "alias", alias);
    }

    if (xmlrpc_struct_has_key (env, activation_info, "service")) {
        RCD_XMLRPC_STRUCT_GET_STRING (env, activation_info,
                                      "service", service_identifier);

        service = service_lookup (service_identifier);

        if (!service || !g_type_is_a (G_TYPE_FROM_INSTANCE (service),
                                      RCD_TYPE_WORLD_REMOTE))
        {
            xmlrpc_env_set_fault_formatted (env, RCD_RPC_FAULT_INVALID_SERVICE,
                                            "Unable to find service '%s'",
                                            service_identifier);
            goto cleanup;
        }
    } else {
        service = NULL;

        if (rc_world_multi_foreach_subworld_by_type (
                RC_WORLD_MULTI (rc_get_world ()),
                RCD_TYPE_WORLD_REMOTE,
                get_singleton_remote_cb,
                &service) < 0)
        {
            xmlrpc_env_set_fault_formatted (env, RCD_RPC_FAULT_INVALID_SERVICE,
                                            "You must specify a specific service");
            goto cleanup;
        }
    }
    
    if (!rcd_world_remote_activate (RCD_WORLD_REMOTE (service),
                                    activation_code, email, alias, &err_msg))
    {
        xmlrpc_env_set_fault_formatted (env, RCD_RPC_FAULT_CANT_ACTIVATE,
                                        "%s", err_msg);
        g_free (err_msg);
        goto cleanup;
    }

cleanup:
    if (env->fault_occurred)
        return NULL;

    return xmlrpc_build_value (env, "i", 0);
}

static void
heartbeat_refresh_world_cb (gpointer user_data)
{
    rc_world_refresh (rc_get_world ());
}

void
rcd_rpc_service_register_methods (void)
{
    rcd_rpc_register_method ("rcd.service.list",
                             service_list,
                             "view", NULL);
    rcd_rpc_register_method ("rcd.service.add",
                             service_add,
                             "superuser", NULL);
    rcd_rpc_register_method ("rcd.service.remove",
                             service_remove,
                             "superuser", NULL);
    rcd_rpc_register_method ("rcd.service.get_mirrors",
                             service_get_mirrors,
                             "view", NULL);
    rcd_rpc_register_method ("rcd.service.set_url",
                             service_set_url,
                             "superuser", NULL);
    rcd_rpc_register_method ("rcd.service.refresh",
                             service_refresh,
                             "view", NULL);
    rcd_rpc_register_method ("rcd.service.refresh_blocking",
                             service_refresh_blocking,
                             "view", NULL);
    rcd_rpc_register_method ("rcd.service.activate",
                             service_activate,
                             "superuser", NULL);

    rcd_heartbeat_register_func (heartbeat_refresh_world_cb, NULL);
}
