/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-rpc-users.c
 *
 * Copyright (C) 2002 Ximian, Inc.
 *
 */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * verison 2, as published by the Free Software Foundation.
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
#include "rcd-rpc-users.h"

#include "rcd-rpc.h"
#include "rcd-rpc-util.h"
#include "rcd-identity.h"

struct GetPrivInfo {
    xmlrpc_env *env;
    xmlrpc_value *array;
};

static void
get_priv_cb (RCDPrivileges priv,
             const char   *priv_name,
             gpointer      user_data)
{
    struct GetPrivInfo *info = user_data;
    xmlrpc_value *value;

    value = xmlrpc_build_value (info->env, "s", priv_name);
    
    xmlrpc_array_append_item (info->env, info->array, value);
    XMLRPC_FAIL_IF_FAULT (info->env);

 cleanup:
    xmlrpc_DECREF (value);
}

static xmlrpc_value *
users_get_valid_privileges (xmlrpc_env   *env,
                            xmlrpc_value *param_array,
                            void         *user_data)
{
    struct GetPrivInfo info;

    info.env = env;
    info.array = xmlrpc_build_value (env, "()");

    rcd_privileges_foreach (get_priv_cb, &info);

    return info.array;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static xmlrpc_value *
users_has_privilege (xmlrpc_env   *env,
                     xmlrpc_value *param_array,
                     void         *user_data)
{
    char *privilege;
    xmlrpc_value *result = NULL;
    RCDRPCMethodData *method_data;

    xmlrpc_parse_value (env, param_array, "(s)", &privilege);
    XMLRPC_FAIL_IF_FAULT (env);

    method_data = rcd_rpc_get_method_data ();
    result = xmlrpc_build_value (
        env, "i",
        rcd_identity_approve_action (method_data->identity,
                                     rcd_privileges_from_string (privilege)));

cleanup:
    if (env->fault_occurred)
        return NULL;
    else
        return result;
} /* users_has_privilege */

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

struct GetAllInfo {
    xmlrpc_env *env;
    xmlrpc_value *array;
};

static void
get_all_cb (RCDIdentity *id,
            gpointer user_data)
{
    struct GetAllInfo *info = user_data;
    char *auth_str;
    xmlrpc_value *value;

    auth_str = rcd_privileges_to_string (id->privileges);

    value = xmlrpc_build_value (info->env,
                                "(ss)",
                                id->username,
                                auth_str);

    g_free (auth_str);

    xmlrpc_array_append_item (info->env, info->array, value);
    XMLRPC_FAIL_IF_FAULT (info->env);

 cleanup:
    xmlrpc_DECREF (value);
}

static xmlrpc_value *
users_get_all (xmlrpc_env   *env,
               xmlrpc_value *param_array,
               void         *user_data)
{
    struct GetAllInfo info;

    info.env = env;
    info.array = xmlrpc_build_value (env, "()");

    rcd_identity_foreach_from_password_file (get_all_cb, &info);

    return info.array;
}

static xmlrpc_value *
users_update (xmlrpc_env   *env,
              xmlrpc_value *param_array,
              void         *user_data)
{
    RCDIdentity *id = NULL;
    char *username, *password, *privileges;
    gboolean success = FALSE;
    xmlrpc_value *ret_value = NULL;

    xmlrpc_parse_value (env, param_array, "(sss)",
                        &username, &password, &privileges);
    XMLRPC_FAIL_IF_FAULT (env);

    if (! (rcd_identity_well_formed_username (username)
           && rcd_identity_well_formed_password (password)))
        goto cleanup;

    id = rcd_identity_new ();

    id->username   = g_strdup (username);
    
    if (strcmp (password, "-*-unchanged-*-"))
        id->password   = g_strdup (password);
    else
        id->password = NULL;
    
    if (strcmp (privileges, "-*-unchanged-*-"))
        id->privileges = rcd_privileges_from_string (privileges);
    else
        id->privileges = 0;



    success = rcd_identity_update_password_file (id);

 cleanup:
    if (! env->fault_occurred) {
        ret_value = xmlrpc_build_value (env, "i", success ? 1 : 0);
        if (env->fault_occurred)
            ret_value = NULL;
    }
    
    rcd_identity_free (id);

    return ret_value;
}

static xmlrpc_value *
users_remove (xmlrpc_env   *env,
              xmlrpc_value *param_array,
              void         *user_data)
{
    char *username;
    gboolean rv = FALSE;
    xmlrpc_value *value = NULL;
    
    xmlrpc_parse_value (env, param_array, "(s)", &username);
    XMLRPC_FAIL_IF_FAULT (env);

    if (username && *username) {
        rv = rcd_identity_remove_from_password_file (username);
    }

    value = xmlrpc_build_value (env, "i", rv ? 1 : 0);

 cleanup:
    return value;
}

void
rcd_rpc_users_register_methods (void)
{
    rcd_rpc_register_method ("rcd.users.get_valid_privileges",
                             users_get_valid_privileges,
                             "view",
                             NULL);

    rcd_rpc_register_method ("rcd.users.has_privilege",
                             users_has_privilege,
                             NULL,
                             NULL);

    rcd_rpc_register_method ("rcd.users.get_all",
                             users_get_all,
                             "view",
                             NULL);

    rcd_rpc_register_method ("rcd.users.update",
                             users_update,
                             "superuser",
                             NULL);

    rcd_rpc_register_method ("rcd.users.remove",
                             users_remove,
                             "superuser",
                             NULL);

}
