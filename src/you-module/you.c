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
#include "rc-you-query.h"
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

static gboolean
add_patch_cb (RCYouPatch *patch, gpointer user_data)
{
    RCYouPatchSList **patches = (RCYouPatchSList **) user_data;

    *patches = g_slist_prepend (*patches, rc_you_patch_ref (patch));
    return TRUE;
} /* add_patch_cb */

static xmlrpc_value *
you_search (xmlrpc_env   *env,
            xmlrpc_value *param_array,
            void         *user_data)
{
    RCWorld *world = (RCWorld *) user_data;
    xmlrpc_value *value = NULL;
    int size = 0;
    RCDQueryPart *parts = NULL;
    int i;
    RCYouPatchSList *rc_you_patches = NULL;
    xmlrpc_value *xmlrpc_patches = NULL;

    xmlrpc_parse_value (env, param_array, "(V)", &value);
    XMLRPC_FAIL_IF_FAULT (env);

    size = xmlrpc_array_size (env, value);
    XMLRPC_FAIL_IF_FAULT (env);

    parts = g_new0 (RCDQueryPart, size + 1);
    for (i = 0; i < size; i++) {
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
    
    rc_you_query_patches (world, parts, add_patch_cb, &rc_you_patches);

    xmlrpc_patches = rc_you_patch_slist_to_xmlrpc_array (rc_you_patches, env);

cleanup:
    if (parts) {
        for (i = 0; i < size; i++) {
            g_free (parts[i].key);
            g_free (parts[i].query_str);
        }
        g_free (parts);
    }

    if (rc_you_patches) {
        rc_you_patch_slist_unref (rc_you_patches);
        g_slist_free (rc_you_patches);
    }

    if (env->fault_occurred)
        return NULL;

    return xmlrpc_patches;
} /* you_search */

typedef struct {
    RCWorld *world;
    RCYouPatch *patch;
    RCYouPatch *installed_patch;

    gboolean subscribed_only;
} LatestVersionInfo;

static gboolean
find_latest_version (RCYouPatch *patch, gpointer user_data)
{
    LatestVersionInfo *info = user_data;
    RCPackman *packman = rc_packman_get_global ();

    if (info->subscribed_only
        && !rc_channel_is_subscribed (patch->channel))
        return TRUE;

    /*
     * First check to see if we're newer than the version already installed
     * on the system, if there is one.  That's filled out below, in
     * find_latest_installed_version().
     */
    if (info->installed_patch) {
        if (rc_packman_version_compare
            (packman,
             RC_PACKAGE_SPEC (patch),
             RC_PACKAGE_SPEC (info->installed_patch)) <= 0)
            return TRUE;
    }

    if (!info->patch)
        info->patch = patch;
    else {
        if (rc_packman_version_compare
            (packman, 
             RC_PACKAGE_SPEC (patch),
             RC_PACKAGE_SPEC (info->patch)) > 0)
            info->patch = patch;
    }

    return TRUE;
} /* find_latest_version */

static gboolean
find_latest_installed_version (RCYouPatch *patch, gpointer user_data)
{
    LatestVersionInfo *info = user_data;
    RCPackman *packman = rc_packman_get_global ();

    if (!info->installed_patch)
        info->installed_patch = patch;
    else {
        if (rc_packman_version_compare
            (packman, 
             RC_PACKAGE_SPEC (patch),
             RC_PACKAGE_SPEC (info->installed_patch)) > 0)
            info->installed_patch = patch;
    }
    return TRUE;
} /* find_latest_installed_version */

static xmlrpc_value *
you_find_latest_version (xmlrpc_env   *env,
                         xmlrpc_value *param_array,
                         void         *user_data)
{
    RCWorld *world = (RCWorld *) user_data;
    char *name = NULL;
    gboolean subscribed_only;
    LatestVersionInfo info;
    xmlrpc_value *result = NULL;

    xmlrpc_parse_value (env, param_array, "(sb)", &name, &subscribed_only);
    XMLRPC_FAIL_IF_FAULT (env);

    info.world = world;
    info.patch = NULL;
    info.installed_patch = NULL;
    info.subscribed_only = subscribed_only;

    rc_world_multi_foreach_patch_by_name
        (RC_WORLD_MULTI (world), name, RC_CHANNEL_SYSTEM,
         find_latest_installed_version, &info);
    rc_world_multi_foreach_patch_by_name
        (RC_WORLD_MULTI (world), name, RC_CHANNEL_NON_SYSTEM,
         find_latest_version, &info);

    if (!info.patch) {
        if (info.installed_patch) {
            /* No version in a channel newer than what is on the system. */
            xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PACKAGE_IS_NEWEST,
                                  "Installed version is newer than the "
                                  "newest available version");
        } else {
            /* Can't find a patch by that name at all. */
            xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PACKAGE_NOT_FOUND,
                                  "Couldn't find patch");
        }

        return NULL;
    }

    result = rc_you_patch_to_xmlrpc (info.patch, env);

 cleanup:
    if (env->fault_occurred)
        return NULL;

    return result;
}

static xmlrpc_value *
you_transaction (xmlrpc_env   *env,
                 xmlrpc_value *param_array,
                 void         *user_data)
{
    xmlrpc_value *xmlrpc_install_patches;
    RCDTransactionFlags flags;
    char *trid, *client_id, *client_version;
    RCYouPatchSList *install_patches = NULL;
    RCDRPCMethodData *method_data;
    RCYouTransaction *transaction;
    RCPending *download_pending, *transaction_pending, *step_pending;
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
    step_pending = rc_you_transaction_get_step_pending (transaction);

    g_object_unref (transaction);

    result = xmlrpc_build_value (env, "(iii)",
                                 download_pending != NULL ?
                                 rc_pending_get_id (download_pending) : -1,

                                 transaction_pending != NULL ?
                                 rc_pending_get_id (transaction_pending) : -1,

                                 step_pending != NULL ?
                                 rc_pending_get_id (step_pending) : -1);

    XMLRPC_FAIL_IF_FAULT (env);

cleanup:
    if (install_patches) {
        rc_you_patch_slist_unref (install_patches);
        g_slist_free (install_patches);
    }

    return result;
}

static xmlrpc_value *
you_license (xmlrpc_env   *env,
             xmlrpc_value *param_array,
             void         *user_data)
{
    xmlrpc_value *xmlrpc_patches = NULL;
    RCYouPatchSList *patches = NULL;
    GSList *licenses = NULL;
    xmlrpc_value *xmlrpc_licenses = NULL;
    GSList *iter;

    xmlrpc_parse_value (env, param_array, "(A)", &xmlrpc_patches);
    XMLRPC_FAIL_IF_FAULT (env);

    patches = rc_xmlrpc_array_to_rc_you_patch_slist
        (xmlrpc_patches, env, RC_YOU_PATCH_FROM_XMLRPC_PATCH);
    XMLRPC_FAIL_IF_FAULT (env);

    licenses = rc_you_patch_slist_lookup_licenses (patches);

    xmlrpc_licenses = xmlrpc_build_value (env, "()");
    XMLRPC_FAIL_IF_FAULT (env);

    for (iter = licenses; iter; iter = iter->next) {
        xmlrpc_value *xmlrpc_text;

        xmlrpc_text = xmlrpc_build_value (env, "s", (char *) iter->data);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_array_append_item (env, xmlrpc_licenses, xmlrpc_text);
        XMLRPC_FAIL_IF_FAULT (env);
        xmlrpc_DECREF (xmlrpc_text);
    }

 cleanup:

    if (patches) {
        rc_you_patch_slist_unref (patches);
        g_slist_free (patches);
    }

    g_slist_free (licenses);

    if (env->fault_occurred)
        return NULL;

    return xmlrpc_licenses;
}

static xmlrpc_value *
you_info (xmlrpc_env   *env,
          xmlrpc_value *param_array,
          void         *user_data)
{
    xmlrpc_value *xmlrpc_patch = NULL;
    RCYouPatch *patch = NULL;
    xmlrpc_value *result = NULL;

    xmlrpc_parse_value (env, param_array, "(V)", &xmlrpc_patch);
    XMLRPC_FAIL_IF_FAULT (env);

    patch = rc_xmlrpc_to_rc_you_patch (xmlrpc_patch, env,
                                       RC_YOU_PATCH_FROM_XMLRPC_PATCH);
    XMLRPC_FAIL_IF_FAULT (env);

    g_assert (patch != NULL);
    
    result = xmlrpc_struct_new (env);
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_SET_STRING (env, result, "summary", patch->summary);
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_SET_STRING (env, result, "description",
                                  patch->description);
    XMLRPC_FAIL_IF_FAULT (env);

 cleanup:
    if (env->fault_occurred) {
        if (patch)
            rc_you_patch_unref (patch);
        if (result)
            xmlrpc_DECREF (result);
        return NULL;
    }

    return result;
}

/*****************************************************************************/

void rcd_module_load (RCDModule *);

void
rcd_module_load (RCDModule *module)
{
    RCWorld *world;

    module->name = "rcd.you";
    module->description = "Module for Yast Online Update";
    module->version = 0;
    module->interface_major = 1;
    module->interface_minor = 0;

    rcd_module = module;
    world = rc_get_world ();

    g_signal_connect (RC_WORLD_MULTI (world),
                      "subworld_added",
                      G_CALLBACK (subworld_added_cb),
                      NULL);

    rcd_rpc_register_method ("rcd.you.search", you_search,
                             "view", world);
    rcd_rpc_register_method ("rcd.you.find_latest_version",
                             you_find_latest_version,
                             "view", world);
    rcd_rpc_register_method ("rcd.you.transact", you_transaction,
                             "superuser", NULL);
    rcd_rpc_register_method ("rcd.you.licenses", you_license,
                             "view", NULL);
    rcd_rpc_register_method ("rcd.you.patch_info", you_info,
                             "view", NULL);

} /* rcd_module_load */
