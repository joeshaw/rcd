/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * you.c
 *
 * Copyright (C) 2004 Novell, Inc.
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

#include <sys/utsname.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <xmlrpc.h>

#include <rc-world-system.h>
#include <rcd-module.h>
#include <rcd-xmlrpc.h>
#include <rcd-rpc-util.h>
#include <rcd-rpc.h>
#include <rcd-world-remote.h>
#include <rcd-transaction.h>

#include "rc-you-patch.h"
#include "rc-world-you.h"
#include "you-util.h"
#include "rc-you-transaction.h"

static RCDModule *rcd_module = NULL;

int rcd_module_major_version = RCD_MODULE_MAJOR_VERSION;
int rcd_module_minor_version = RCD_MODULE_MINOR_VERSION;


/*****************************************************************************/

static void
subworld_added_cb (RCWorldMulti *multi,
                   RCWorld      *subworld,
                   gpointer      user_data)
{
    if (!RCD_IS_WORLD_REMOTE (subworld) &&
        !RC_IS_WORLD_SYSTEM (subworld))
        return;

    rc_world_add_patches (RC_WORLD (subworld), NULL);

    g_signal_connect (RC_WORLD (subworld),
                      "refreshed",
                      G_CALLBACK (rc_world_add_patches),
                      NULL);
}

/*****************************************************************************/

static xmlrpc_value *
you_search (xmlrpc_env   *env,
            xmlrpc_value *param_array,
            void         *user_data)
{
    RCChannel *channel;
    RCWorld *world;
    RCYouPatch *patch;
    xmlrpc_value *value;
    xmlrpc_value *param_struct = NULL;
    gchar *name = NULL;
    gchar *channel_id = NULL;

    xmlrpc_parse_value (env, param_array, "(S)",
                        &param_struct);
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_GET_STRING (env, param_struct, "name", name);
    XMLRPC_FAIL_IF_FAULT (env);

    world = rc_get_world ();

    if (xmlrpc_struct_has_key (env, param_struct, "channel")) {
        RCD_XMLRPC_STRUCT_GET_STRING (env, param_struct, "channel", channel_id);
        XMLRPC_FAIL_IF_FAULT (env);

        channel = rc_world_get_channel_by_id (world, channel_id);
        if (!channel) {
            xmlrpc_env_set_fault (env, RCD_RPC_FAULT_INVALID_CHANNEL,
                                  "Unable to find channel");
            goto cleanup;
        }
    } else
        channel = RC_CHANNEL_ANY;

    patch = rc_world_multi_get_patch (RC_WORLD_MULTI (world),
                                      channel,
                                      name);

    if (patch) {
        value = rc_you_patch_to_xmlrpc (patch, env);
        XMLRPC_FAIL_IF_FAULT (env);

        return value;
    } 

    xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PACKAGE_NOT_FOUND,
                          "Patch not found");
 cleanup:
    return NULL;
}

static gboolean
patch_list_cb (RCYouPatch *patch, gpointer user_data)
{
    RCYouPatchSList **patches = user_data;

    *patches = g_slist_prepend (*patches, rc_you_patch_ref (patch));
    return TRUE;
}

static xmlrpc_value *
you_list (xmlrpc_env   *env,
          xmlrpc_value *param_array,
          void         *user_data)
{
    RCYouPatchSList *patches = NULL;
    xmlrpc_value *value;

    rc_world_multi_foreach_patch (RC_WORLD_MULTI (rc_get_world ()),
                                  patch_list_cb,
                                  &patches);

    value = rc_you_patch_slist_to_xmlrpc_array (patches, env);

    rc_you_patch_slist_unref (patches);
    g_slist_free (patches);

    return value;
}

static xmlrpc_value *
you_install (xmlrpc_env   *env,
             xmlrpc_value *param_array,
             void         *user_data)
{
    xmlrpc_value *xmlrpc_install_patches;
    RCDTransactionFlags flags;
    char *trid, *client_id, *client_version;
    RCYouPatchSList *install_patches = NULL;
    RCDRPCMethodData *method_data;
    RCYouTransaction *transaction;
    RCPending *download_pending, *transaction_pending;
    xmlrpc_value *result = NULL;

    /* Before we begin any transaction, expire the package cache. */
    rcd_cache_expire_package_cache ();

    xmlrpc_parse_value (env, param_array, "(Aisss)",
                        &xmlrpc_install_patches,
                        &flags, &trid, &client_id, &client_version);
    XMLRPC_FAIL_IF_FAULT (env);

    install_patches = rc_xmlrpc_array_to_rc_you_patch_slist (
        xmlrpc_install_patches, env, RC_YOU_PATCH_FROM_XMLRPC_PATCH);
    XMLRPC_FAIL_IF_FAULT (env);

    method_data = rcd_rpc_get_method_data ();

    transaction = rc_you_transaction_new ();
    rc_you_transaction_set_id (transaction, trid);
    rc_you_transaction_set_patches (transaction, install_patches);
    rc_you_transaction_set_flags (transaction, flags);
    rc_you_transaction_set_client_info (transaction,
                                        client_id, client_version,
                                        method_data->host,
                                        method_data->identity);

    rc_you_transaction_begin (transaction);

    download_pending = rc_you_transaction_get_download_pending (transaction);
    transaction_pending =
        rc_you_transaction_get_transaction_pending (transaction);

    g_object_unref (transaction);

    result = xmlrpc_build_value (env, "(ii)",
                                 download_pending != NULL ?
                                 rc_pending_get_id (download_pending) : -1,

                                 transaction_pending != NULL ?
                                 rc_pending_get_id (transaction_pending) : -1);
    XMLRPC_FAIL_IF_FAULT (env);

cleanup:
    if (install_patches) {
        rc_you_patch_slist_unref (install_patches);
        g_slist_free (install_patches);
    }

    return result;
}

/*****************************************************************************/

void rcd_module_load (RCDModule *);

void
rcd_module_load (RCDModule *module)
{
    module->name = "rcd.you";
    module->description = "Module for Yast Online Update";
    module->version = 0;
    module->interface_major = 1;
    module->interface_minor = 0;

    rcd_module = module;

    g_signal_connect (RC_WORLD_MULTI (rc_get_world ()),
                      "subworld_added",
                      G_CALLBACK (subworld_added_cb),
                      NULL);

    rcd_rpc_register_method ("rcd.you.list", you_list,
                             "view", NULL);
    rcd_rpc_register_method ("rcd.you.search", you_search,
                             "view", NULL);
    rcd_rpc_register_method ("rcd.you.install", you_install,
                             "superuser", NULL);

} /* rcd_module_load */
