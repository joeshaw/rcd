/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-rpc-users.c
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
#include "rcd-rpc-users.h"

#include "rcd-rpc.h"
#include "rcd-rpc-util.h"
#include "rcd-identity.h"

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
    RCDIdentity *id;
    char *username, *password, *privileges;
    gboolean success;
    xmlrpc_value *ret_value = NULL;

    id = rcd_identity_new ();
    xmlrpc_parse_value (env, param_array, "(sss)",
                        &username, &password, &privileges);
    XMLRPC_FAIL_IF_FAULT (env);

    id->username   = g_strdup (username);
    id->password   = g_strdup (password);
    id->privileges = rcd_privileges_from_string (privileges);

    success = rcd_identity_update_password_file (id);

    ret_value = xmlrpc_build_value (env, "i", success ? 1 : 0);
    XMLRPC_FAIL_IF_FAULT (env);

 cleanup:
    rcd_identity_free (id);

    return ret_value;
}

static xmlrpc_value *
users_remove (xmlrpc_env   *env,
              xmlrpc_value *param_array,
              void         *user_data)
{
    return NULL;
}

void
rcd_rpc_users_register_methods (void)
{
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