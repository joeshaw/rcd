/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-rpc-packsys.c
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
#include "rcd-rpc-packsys.h"

#include <sys/utsname.h>

#include <xmlrpc.h>

#include "rcd-cache.h"
#include "rcd-fetch.h"
#include "rcd-heartbeat.h"
#include "rcd-package-locks.h"
#include "rcd-pending.h"
#include "rcd-prefs.h"
#include "rcd-query-packages.h"
#include "rcd-rollback.h"
#include "rcd-rpc.h"
#include "rcd-rpc-util.h"
#include "rcd-subscriptions.h"
#include "rcd-transaction.h"

#define RCD_REFRESH_INVALID ((gpointer) 0xdeadbeef)

static void
add_channel_cb (RCChannel *channel, gpointer user_data)
{
    GSList **slist = user_data;
    *slist = g_slist_prepend (*slist, channel);
}

static xmlrpc_value *
packsys_get_channels (xmlrpc_env   *env,
                      xmlrpc_value *param_array,
                      void         *user_data)
{
    RCWorld *world = user_data;
    xmlrpc_value *channel_array;
    GSList *channel_list = NULL, *iter;

    rc_world_foreach_channel (world,
                              add_channel_cb,
                              &channel_list);

    channel_array = xmlrpc_build_value (env, "()");

    for (iter = channel_list; iter != NULL; iter = iter->next) {
        RCChannel *channel = iter->data;
        xmlrpc_value *value;

        value = rcd_rc_channel_to_xmlrpc (channel, env);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_array_append_item (env, channel_array, value);
        XMLRPC_FAIL_IF_FAULT (env);

        /*
         * Adding the value to the array increments its refcount, so release
         * our ref and let the array own it.
         */
        xmlrpc_DECREF(value);
    }

 cleanup:
    g_slist_free (channel_list);
    
    if (env->fault_occurred)
        return NULL;

    return channel_array;
}

static xmlrpc_value *
packsys_refresh_channel (xmlrpc_env   *env,
                         xmlrpc_value *param_array,
                         void         *user_data)
{
    RCWorld *world = user_data;
    xmlrpc_value *value = NULL;
    RCChannel *channel;
    guint32 channel_id;
    gint pending_id = -1;

    xmlrpc_parse_value (env, param_array, "(i)", &channel_id);
    XMLRPC_FAIL_IF_FAULT (env);

    channel = rc_world_get_channel_by_id (world, channel_id);
    if (channel) {
        pending_id = rcd_fetch_channel (channel);
        rcd_fetch_channel_icon (channel);
    }

    value = xmlrpc_build_value (env, "i", pending_id);

 cleanup:
    if (env->fault_occurred)
        return NULL;

    return value;
}

static gboolean
check_pending_status_cb (gpointer user_data)
{
    GSList *id_list = user_data;
    GSList *iter;

    for (iter = id_list; iter; iter = iter->next) {
        int id = GPOINTER_TO_INT (iter->data);
        RCDPending *pending = rcd_pending_lookup_by_id (id);
        RCDPendingStatus status = rcd_pending_get_status (pending);

        if (status == RCD_PENDING_STATUS_PRE_BEGIN ||
            status == RCD_PENDING_STATUS_RUNNING ||
            status == RCD_PENDING_STATUS_BLOCKING)
            return TRUE;
    }

    g_slist_free (id_list);

    rcd_transaction_unlock ();

    return FALSE;
} /* check_pending_status_cb */

static void
refresh_channels_cb (gpointer user_data)
{
    GSList *id_list;
    GSList **ret_list = user_data;

    rcd_transaction_lock ();

    if (!rcd_fetch_channel_list ()) {
        if (ret_list)
            *ret_list = RCD_REFRESH_INVALID;
        rcd_transaction_unlock ();
        return;
    }

    rcd_subscriptions_load ();

    rcd_fetch_all_channel_icons (TRUE);
    id_list = rcd_fetch_all_channels ();

    if (ret_list == NULL) {
        g_slist_free (id_list);
        id_list = NULL;
    } else
        *ret_list = id_list;

    g_idle_add (check_pending_status_cb, id_list);
} /* refresh_channels_cb */

static xmlrpc_value *
packsys_refresh_all_channels (xmlrpc_env   *env,
                              xmlrpc_value *param_array,
                              void         *user_data)
{
    xmlrpc_value *value = NULL;
    GSList *ret_list = NULL, *iter;

    if (rcd_transaction_is_locked ()) {
        xmlrpc_env_set_fault (env, RCD_RPC_FAULT_LOCKED,
                              "Transaction lock in place");
        return NULL;
    }

    refresh_channels_cb (&ret_list);

    if (ret_list == RCD_REFRESH_INVALID) {
        xmlrpc_env_set_fault (
            env, RCD_RPC_FAULT_CANT_REFRESH,
            "Unable to download channel data.  Using cached data");
        goto cleanup;
    }

    value = xmlrpc_build_value (env, "()");
    XMLRPC_FAIL_IF_FAULT (env);

    for (iter = ret_list; iter != NULL; iter = iter->next) {
        int id = GPOINTER_TO_INT (iter->data);
        xmlrpc_value *idval;

        idval = xmlrpc_build_value (env, "i", id);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_array_append_item (env, value, idval);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_DECREF (idval);
    }
    
 cleanup:
    if (env->fault_occurred)
        return NULL;

    return value;
} /* packsys_refresh_all_channels */

static xmlrpc_value *
packsys_get_channel_icon (xmlrpc_env   *env,
                          xmlrpc_value *param_array,
                          void         *user_data)
{
    RCWorld *world = user_data;
    int channel_id;
    RCChannel *channel;
    char *local_file;
    RCBuffer *buf;
    xmlrpc_value *value = NULL;

    xmlrpc_parse_value (env, param_array, "(i)", &channel_id);
    XMLRPC_FAIL_IF_FAULT (env);

    channel = rc_world_get_channel_by_id (world, channel_id);
    if (!channel) {
        xmlrpc_env_set_fault_formatted (env, RCD_RPC_FAULT_INVALID_CHANNEL,
                                        "Unable to find channel %d",
                                        channel_id);
        goto cleanup;
    }

    local_file = rcd_cache_get_local_filename (
        rcd_cache_get_icon_cache (channel_id),
        rc_channel_get_icon_file (channel));

    if (!local_file) {
        xmlrpc_env_set_fault_formatted (env, RCD_RPC_FAULT_NO_ICON,
                                        "Can't get icon for channel '%s' (%d)",
                                        rc_channel_get_name (channel),
                                        channel_id);
        goto cleanup;
    }

    buf = rc_buffer_map_file (local_file);
    if (!buf) {
        xmlrpc_env_set_fault_formatted (env, RCD_RPC_FAULT_NO_ICON,
                                        "Unable to open icon for channel "
                                        "'%s' (%d)",
                                        rc_channel_get_name (channel),
                                        channel_id);
        goto cleanup;
    }

    value = xmlrpc_build_value (env, "6", buf->data, buf->size);

    rc_buffer_unmap_file (buf);

    XMLRPC_FAIL_IF_FAULT (env);

cleanup:
    if (env->fault_occurred)
        return NULL;

    return value;
} /* packsys_get_channel_icon */

static xmlrpc_value *
packsys_subscribe (xmlrpc_env   *env,
                   xmlrpc_value *param_array,
                   void         *user_data)
{
    RCWorld *world = user_data;
    RCChannel *channel = NULL;
    xmlrpc_value *value = NULL;
    gint channel_id = -1;
    gboolean success = FALSE;

    xmlrpc_parse_value (env, param_array, "(i)", &channel_id);
    XMLRPC_FAIL_IF_FAULT (env);

    channel = rc_world_get_channel_by_id (world, channel_id);
    if (channel != NULL) {

        if (! rc_channel_subscribed (channel)) {
            rc_channel_set_subscription (channel, TRUE);
            success = rcd_subscriptions_save ();

            /* If we couldn't save our subscription file, undo the change.
               This keeps us in sync with the xml file on disk, and it
               keeps us from showing the channel as being subed even
               though we (hopefully!) reported an error to the user. */
            if (! success)
                rc_channel_set_subscription (channel, FALSE);
        } else {
            /* channel is already subscribed */
            success = TRUE;
        }
    }

    value = xmlrpc_build_value (env, "i", success ? 1 : 0);

 cleanup:
    if (env->fault_occurred)
        return NULL;
        
    return value;
}

static xmlrpc_value *
packsys_unsubscribe (xmlrpc_env   *env,
                     xmlrpc_value *param_array,
                     void         *user_data)
{
    RCWorld *world = user_data;
    RCChannel *channel = NULL;
    xmlrpc_value *value = NULL;
    gint channel_id = -1;
    gboolean success = FALSE;

    xmlrpc_parse_value (env, param_array, "(i)", &channel_id);
    XMLRPC_FAIL_IF_FAULT (env);

    channel = rc_world_get_channel_by_id (world, channel_id);
    if (channel != NULL) {

        if (rc_channel_subscribed (channel)) {
            rc_channel_set_subscription (channel, FALSE);
            success = rcd_subscriptions_save ();

            /* If we couldn't save our subscription file, undo the change.
               This keeps us in sync with the xml file on disk, and it
               keeps us from showing the channel as being unsubed even
               though we (hopefully!) reported an error to the user. */
            if (! success)
                rc_channel_set_subscription (channel, TRUE);
        } else {
            /* channel is already unsubscribed */
            success = TRUE;
        }
    }

    value = xmlrpc_build_value (env, "i", success ? 1 : 0);

 cleanup:
    if (env->fault_occurred)
        return NULL;
        
    return value;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

struct BuildUpdatesInfo {
    xmlrpc_env *env;
    xmlrpc_value *array;
    gboolean failed;
};

static void
build_updates_list (RCPackage *old,
                    RCPackage *nuevo,
                    gpointer   user_data)
{
    struct BuildUpdatesInfo *info = user_data;
    RCPackageUpdateSList *iter;
    xmlrpc_value *pair;
    xmlrpc_value *old_xmlrpc, *new_xmlrpc, *history;

    if (info->failed)
        return;

    old_xmlrpc = rcd_rc_package_to_xmlrpc (old, info->env);
    new_xmlrpc = rcd_rc_package_to_xmlrpc (nuevo, info->env);

    history = xmlrpc_build_value (info->env, "()");
    XMLRPC_FAIL_IF_FAULT (info->env);

    iter = nuevo->history;
    while (iter != NULL) {

        RCPackageUpdate *update = iter->data;

        if (rc_packman_version_compare (
                rc_world_get_packman (rc_get_world ()),
                RC_PACKAGE_SPEC (old),
                RC_PACKAGE_SPEC (update)) < 0)
        {
            xmlrpc_value *desc;
            
            if (update->description && *update->description) {
                desc = xmlrpc_build_value (info->env, "s", update->description);
                xmlrpc_array_append_item (info->env, history, desc);
                xmlrpc_DECREF (desc);
            }
            
            iter = iter->next;

        } else {
            iter = NULL;
        }
    }
    
    pair = xmlrpc_build_value (info->env,
                               "(VVV)",
                               old_xmlrpc,
                               new_xmlrpc,
                               history);
    XMLRPC_FAIL_IF_FAULT (info->env);

    xmlrpc_array_append_item (info->env,
                              info->array, pair);
    XMLRPC_FAIL_IF_FAULT (info->env);

    xmlrpc_DECREF (old_xmlrpc);
    xmlrpc_DECREF (new_xmlrpc);
    xmlrpc_DECREF (history);
    xmlrpc_DECREF (pair);

 cleanup:
    if (info->env->fault_occurred)
        info->failed = TRUE;
}

static xmlrpc_value *
packsys_get_updates (xmlrpc_env   *env,
                     xmlrpc_value *param_array,
                     void         *user_data)
{
    struct BuildUpdatesInfo info;
    RCWorld *world = user_data;
    xmlrpc_value *update_array = NULL;

    update_array = xmlrpc_build_value (env, "()");
    XMLRPC_FAIL_IF_FAULT (env);

    info.env    = env;
    info.array  = update_array;
    info.failed = FALSE;

    rc_world_foreach_system_upgrade (world,
                                     build_updates_list,
                                     &info);

 cleanup:
    if (env->fault_occurred || info.failed)
        return NULL;

    return update_array;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

struct UpdateSummaryInfo {
    int total;
    int by_importance[RC_IMPORTANCE_LAST];
};

static void
count_updates (RCPackage *old,
               RCPackage *nuevo,
               gpointer   user_data)
{
    struct UpdateSummaryInfo *info = user_data;
    RCPackageUpdate *update;

    /* Filter out updates in unsubscribed channels. */
    if (nuevo->channel
        && ! rc_channel_subscribed (nuevo->channel))
        return;

    update = rc_package_get_latest_update (nuevo);

    if (update) {
        ++info->total;
        ++info->by_importance[update->importance];
    }
}

static xmlrpc_value *
packsys_update_summary (xmlrpc_env   *env,
                        xmlrpc_value *param_array,
                        void         *user_data)
{
    struct UpdateSummaryInfo info;
    RCWorld *world = user_data;
    xmlrpc_value *summary;
    int i;

    summary = xmlrpc_struct_new (env);
    XMLRPC_FAIL_IF_FAULT (env);

    info.total = 0;
    for (i = 0; i < RC_IMPORTANCE_LAST; ++i)
        info.by_importance[i] = 0;

    rc_world_foreach_system_upgrade (world,
                                     count_updates,
                                     &info);

    RCD_XMLRPC_STRUCT_SET_INT (env, summary, "total", info.total);

    for (i = 0; i < RC_IMPORTANCE_LAST; ++i) {
        if (info.by_importance[i] > 0) {
            RCD_XMLRPC_STRUCT_SET_INT (env, summary,
                                       (char *) rc_package_importance_to_string ((RCPackageImportance) i),
                                       info.by_importance[i]);
        }
    }

 cleanup:
    if (env->fault_occurred)
        return NULL;

    return summary;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static void
add_package_cb (RCPackage *package, gpointer user_data)
{
    RCPackageSList **packages = (RCPackageSList **) user_data;

    *packages = g_slist_prepend(*packages, rc_package_ref (package));
} /* add_package_cb */

static xmlrpc_value *
packsys_search (xmlrpc_env   *env,
                xmlrpc_value *param_array,
                void         *user_data)
{
    RCWorld *world = (RCWorld *) user_data;
    xmlrpc_value *value;
    int size = 0;
    RCDQueryPart *parts = NULL;
    int i;
    RCPackageSList *rc_packages = NULL;
    xmlrpc_value *xmlrpc_packages = NULL;

    xmlrpc_parse_value(env, param_array, "(V)", &value);
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
    
    rcd_query_packages (world, parts, add_package_cb, &rc_packages);

    xmlrpc_packages = rcd_rc_package_slist_to_xmlrpc_array(rc_packages, env);

cleanup:
    if (parts) {
        for (i = 0; i < size; i++) {
            g_free (parts[i].key);
            g_free (parts[i].query_str);
        }
        g_free (parts);
    }

    if (rc_packages)
        rc_package_slist_unref(rc_packages);

    if (env->fault_occurred)
        return NULL;

    return xmlrpc_packages;
} /* packsys_search */

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static xmlrpc_value *
packsys_query_file (xmlrpc_env   *env,
                    xmlrpc_value *param_array,
                    void         *user_data)
{
    RCPackage *rc_package;
    xmlrpc_value *value;
    xmlrpc_value *xmlrpc_package = NULL;

    xmlrpc_parse_value(env, param_array, "(V)", &value);
    XMLRPC_FAIL_IF_FAULT(env);

    rc_package = rcd_xmlrpc_to_rc_package (
        value, env, RCD_PACKAGE_FROM_FILE | RCD_PACKAGE_FROM_STREAMED_PACKAGE);
    XMLRPC_FAIL_IF_FAULT(env);

    if (!rc_package) {
        xmlrpc_env_set_fault(env, RCD_RPC_FAULT_PACKAGE_NOT_FOUND,
                             "Couldn't get package from file");
        return NULL;
    }
    
    xmlrpc_package = rcd_rc_package_to_xmlrpc(rc_package, env);
    
    rc_package_unref(rc_package);

cleanup:
    if (env->fault_occurred)
        return NULL;

    return xmlrpc_package;
} /* packsys_query_file */

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

typedef struct {
    RCWorld *world;
    RCPackage *package;
    RCPackage *installed_package;

    gboolean subscribed_only;
} LatestVersionClosure;

static void
find_latest_version (RCPackage *package, gpointer user_data)
{
    LatestVersionClosure *closure = user_data;
    RCPackman *packman = rc_world_get_packman (closure->world);

    if (closure->subscribed_only && !rc_channel_subscribed (package->channel))
        return;

    /*
     * First check to see if we're newer than the version already installed
     * on the system, if there is one.  That's filled out below, in
     * find_latest_installed_version().
     */
    if (closure->installed_package) {
        if (rc_packman_version_compare (
                packman,
                RC_PACKAGE_SPEC (package),
                RC_PACKAGE_SPEC (closure->installed_package)) <= 0)
            return;
    }
        
    if (!closure->package)
        closure->package = package;
    else {
        if (rc_packman_version_compare (
                packman, 
                RC_PACKAGE_SPEC (package),
                RC_PACKAGE_SPEC (closure->package)) > 0)
            closure->package = package;
    }
} /* find_latest_version */

static void
find_latest_installed_version (RCPackage *package, gpointer user_data)
{
    LatestVersionClosure *closure = user_data;
    RCPackman *packman = rc_world_get_packman (closure->world);

    if (!closure->installed_package)
        closure->installed_package = package;
    else {
        if (rc_packman_version_compare (
                packman, 
                RC_PACKAGE_SPEC (package),
                RC_PACKAGE_SPEC (closure->installed_package)) > 0)
            closure->installed_package = package;
    }
} /* find_latest_installed_version */

static xmlrpc_value *
packsys_find_latest_version (xmlrpc_env   *env,
                             xmlrpc_value *param_array,
                             void         *user_data)
{
    RCWorld *world = (RCWorld *) user_data;
    char *name;
    gboolean subscribed_only;
    LatestVersionClosure closure;
    xmlrpc_value *result = NULL;

    xmlrpc_parse_value (env, param_array, "(sb)", &name, &subscribed_only);
    XMLRPC_FAIL_IF_FAULT (env);

    closure.world = world;
    closure.package = NULL;
    closure.installed_package = NULL;
    closure.subscribed_only = subscribed_only;

    rc_world_foreach_package_by_name (
        world, name, RC_WORLD_SYSTEM_PACKAGES,
        find_latest_installed_version, &closure);
    rc_world_foreach_package_by_name (
        world, name, RC_WORLD_ANY_NON_SYSTEM, find_latest_version, &closure);

    if (!closure.package) {
        if (closure.installed_package) {
            /* No version in a channel newer than what is on the system. */
            xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PACKAGE_IS_NEWEST,
                                  "Installed version is newer than the "
                                  "newest available version");
        }
        else {
            /* Can't find a package by that name at all. */
            xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PACKAGE_NOT_FOUND,
                                  "Couldn't find package");
        }

        return NULL;
    }
    
    result = rcd_rc_package_to_xmlrpc(closure.package, env);

cleanup:
    if (env->fault_occurred)
        return NULL;

    return result;
} /* packsys_find_latest_version */

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static xmlrpc_value *
packsys_package_info (xmlrpc_env   *env,
                      xmlrpc_value *param_array,
                      void         *user_data)
{
    xmlrpc_value *xmlrpc_package;
    RCPackage *package;
    xmlrpc_value *result = NULL;

    xmlrpc_parse_value (env, param_array, "(V)", &xmlrpc_package);
    XMLRPC_FAIL_IF_FAULT (env);

    package = rcd_xmlrpc_to_rc_package (
        xmlrpc_package, env, RCD_PACKAGE_FROM_ANY);
    XMLRPC_FAIL_IF_FAULT (env);

    if (package) {
        RCPackageUpdate *update;

        result = xmlrpc_struct_new (env);
        XMLRPC_FAIL_IF_FAULT (env);

        RCD_XMLRPC_STRUCT_SET_STRING (
            env, result, "section",
            rc_package_section_to_string (package->section));

        if (package->file_size) {
            RCD_XMLRPC_STRUCT_SET_INT (
                env, result, "file_size", package->file_size);
        }
        else if ((update = rc_package_get_latest_update (package))) {
            RCD_XMLRPC_STRUCT_SET_INT (
                env, result, "file_size", update->package_size);
        }

        if (package->installed_size) {
            RCD_XMLRPC_STRUCT_SET_INT (
                env, result, "installed_size", package->installed_size);
        }

        RCD_XMLRPC_STRUCT_SET_STRING (
            env, result, "summary", package->summary);
                                   
        RCD_XMLRPC_STRUCT_SET_STRING (
            env, result, "description", package->description);
    }
    else {
        xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PACKAGE_NOT_FOUND,
                              "Couldn't get package");
        return NULL;
    }
    
cleanup:
    return result;
} /* packsys_package_info */

static xmlrpc_value *
packsys_package_dependency_info (xmlrpc_env   *env,
                                 xmlrpc_value *param_array,
                                 void         *user_data)
{
    xmlrpc_value *xmlrpc_package;
    RCPackage *package;
    xmlrpc_value *result = NULL;
    xmlrpc_value *provides, *requires, *conflicts, *obsoletes;

    xmlrpc_parse_value (env, param_array, "(V)", &xmlrpc_package);
    XMLRPC_FAIL_IF_FAULT (env);

    package = rcd_xmlrpc_to_rc_package (
        xmlrpc_package, env, RCD_PACKAGE_FROM_ANY);
    XMLRPC_FAIL_IF_FAULT (env);

    if (package) {

        result = xmlrpc_struct_new (env);
        XMLRPC_FAIL_IF_FAULT (env);

        provides  = rcd_rc_package_dep_array_to_xmlrpc (package->provides_a, env);
        xmlrpc_struct_set_value (env, result, "provides", provides);
        XMLRPC_FAIL_IF_FAULT (env);
        xmlrpc_DECREF (provides);
        
        requires  = rcd_rc_package_dep_array_to_xmlrpc (package->requires_a, env);
        xmlrpc_struct_set_value (env, result, "requires", requires);
        XMLRPC_FAIL_IF_FAULT (env);
        xmlrpc_DECREF (requires);
        
        conflicts = rcd_rc_package_dep_array_to_xmlrpc (package->conflicts_a, env);
        xmlrpc_struct_set_value (env, result, "conflicts", conflicts);
        XMLRPC_FAIL_IF_FAULT (env);
        xmlrpc_DECREF (conflicts);
        
        obsoletes = rcd_rc_package_dep_array_to_xmlrpc (package->obsoletes_a, env);
        xmlrpc_struct_set_value (env, result, "obsoletes", obsoletes);
        XMLRPC_FAIL_IF_FAULT (env);
        xmlrpc_DECREF (obsoletes);

    } else {
        xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PACKAGE_NOT_FOUND,
                              "Couldn't get package");
        return NULL;
    }

 cleanup:
    return result;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static void
check_install_package_auth (xmlrpc_env     *env,
                            RCWorld        *world,
                            RCPackageSList *packages, 
                            RCDIdentity    *identity)
{
    RCPackageSList *iter;
    gboolean install = FALSE;
    gboolean upgrade = FALSE;
    RCDPrivileges req_priv;
    gboolean approved;

    if (!packages)
        return;

    for (iter = packages; iter && !install && !upgrade; iter = iter->next) {
        RCPackage *p = (RCPackage *) iter->data;

        if (rc_world_find_installed_version (world, p))
            upgrade = TRUE;
        else
            install = TRUE;
    }

    if (upgrade) {
        req_priv = rcd_privileges_from_string ("upgrade");
        approved = rcd_identity_approve_action (identity, req_priv);
    
        if (!approved) {
            xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PERMISSION_DENIED,
                                  "Permission denied");
            rc_debug (RC_DEBUG_LEVEL_MESSAGE,
                      "Caller does not have permissions to upgrade packages");
        }
    }

    if (install) {
        req_priv = rcd_privileges_from_string ("install");
        approved = rcd_identity_approve_action (identity, req_priv);
    
        if (!approved) {
            xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PERMISSION_DENIED,
                                  "Permission denied");
            rc_debug (RC_DEBUG_LEVEL_MESSAGE,
                      "Caller does not have permissions to install packages");
        }
    }
} /* check_install_package_auth */

static void
check_remove_package_auth (xmlrpc_env     *env,
                           RCPackageSList *packages, 
                           RCDIdentity    *identity)
{
    RCDPrivileges req_priv;
    gboolean approved;

    if (!packages)
        return;

    req_priv = rcd_privileges_from_string ("remove");
    approved = rcd_identity_approve_action (identity, req_priv);
    
    if (!approved) {
        xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PERMISSION_DENIED,
                              "Permission denied");
        rc_debug (RC_DEBUG_LEVEL_MESSAGE,
                  "Caller does not have permissions to remove packages");
    }
} /* check_remove_package_auth */

static xmlrpc_value *
packsys_transact(xmlrpc_env   *env,
                 xmlrpc_value *param_array,
                 void         *user_data)
{
    RCWorld *world = (RCWorld *) user_data;
    xmlrpc_value *xmlrpc_install_packages;
    xmlrpc_value *xmlrpc_remove_packages;
    RCDTransactionFlags flags;
    char *client_id, *client_version;
    RCPackageSList *install_packages = NULL;
    RCPackageSList *remove_packages = NULL;
    RCDRPCMethodData *method_data;
    int download_id, transaction_id, step_id;
    xmlrpc_value *result = NULL;

    /* Before we begin any transaction, expire the package cache. */
    rcd_cache_expire_package_cache ();

    xmlrpc_parse_value(
        env, param_array, "(AAiss)",
        &xmlrpc_install_packages, &xmlrpc_remove_packages,
        &flags, &client_id, &client_version);
    XMLRPC_FAIL_IF_FAULT(env);

    install_packages = rcd_xmlrpc_array_to_rc_package_slist (
        xmlrpc_install_packages, env,
        RCD_PACKAGE_FROM_FILE | RCD_PACKAGE_FROM_STREAMED_PACKAGE |
        RCD_PACKAGE_FROM_XMLRPC_PACKAGE);
    XMLRPC_FAIL_IF_FAULT (env);

    remove_packages = rcd_xmlrpc_array_to_rc_package_slist (
        xmlrpc_remove_packages, env,
        RCD_PACKAGE_FROM_NAME | RCD_PACKAGE_FROM_XMLRPC_PACKAGE);
    XMLRPC_FAIL_IF_FAULT (env);

    method_data = rcd_rpc_get_method_data ();

    /* Check our permissions to install/upgrade/remove */
    check_install_package_auth (
        env, world, install_packages, method_data->identity);
    XMLRPC_FAIL_IF_FAULT (env);
    
    check_remove_package_auth (
        env, remove_packages, method_data->identity);
    XMLRPC_FAIL_IF_FAULT (env);

    rcd_transaction_begin (NULL,
                           world,
                           install_packages,
                           remove_packages,
                           flags,
                           client_id,
                           client_version,
                           method_data->host,
                           method_data->identity,
                           &download_id,
                           &transaction_id,
                           &step_id);

    result = xmlrpc_build_value (
        env, "(iii)", download_id, transaction_id, step_id);
    XMLRPC_FAIL_IF_FAULT(env);

cleanup:
    if (install_packages)
        rc_package_slist_unref(install_packages);

    if (remove_packages)
        rc_package_slist_unref(remove_packages);

    if (env->fault_occurred)
        return NULL;

    return result;
} /* packsys_transact */

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static xmlrpc_value *
packsys_abort_download(xmlrpc_env   *env,
                       xmlrpc_value *param_array,
                       void         *user_data)
{
    int download_id;
    RCDRPCMethodData *method_data;
    int success;
    xmlrpc_value *result = NULL;

    xmlrpc_parse_value (env, param_array, "(i)", &download_id);

    if (!rcd_transaction_is_valid (download_id)) {
        xmlrpc_env_set_fault (env, RCD_RPC_FAULT_INVALID_TRANSACTION_ID,
                              "Cannot find transaction for that id");
        return NULL;
    }

    method_data = rcd_rpc_get_method_data ();

    success = rcd_transaction_abort (download_id, method_data->identity);

    if (success < 0) {
        xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PERMISSION_DENIED,
                              "Permission denied");
        return NULL;
    }

    result = xmlrpc_build_value (env, "i", success);

    return result;
} /* packsys_abort_download */

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static void
append_dep_info (RCResolverInfo *info, gpointer user_data)
{
    GString *dep_failure_info = user_data;
    gboolean debug = FALSE;

    g_assert (dep_failure_info);

    if (getenv ("RCD_DEBUG_DEPS"))
        debug = TRUE;

    if (debug || rc_resolver_info_is_important (info)) {
        char *msg = rc_resolver_info_to_string (info);

        g_string_append_printf (
            dep_failure_info, "\n%s%s%s",
            (debug && rc_resolver_info_is_error (info)) ? "ERR " : "",
            (debug && rc_resolver_info_is_important (info)) ? "IMP " : "",
            msg);
        g_free (msg);
    }
} /* append_dep_info */

static char *
dep_get_failure_info (RCResolver *resolver)
{
    RCResolverQueue *queue;
    GString *dep_failure_info = g_string_new ("Unresolved dependencies:\n");
    char *str;

    /* FIXME: Choose a best invalid queue */
    queue = (RCResolverQueue *) resolver->invalid_queues->data;

    rc_resolver_context_foreach_info (queue->context, NULL, -1,
                                      append_dep_info, dep_failure_info);

    str = dep_failure_info->str;

    g_string_free (dep_failure_info, FALSE);

    return str;
} /* dep_get_failure_info */

static void
prepend_pkg (RCPackage *pkg, RCPackageStatus status, gpointer user_data)
{
    GSList **slist = user_data;

    if (rc_package_status_is_to_be_installed (status) ||
        (rc_package_status_is_to_be_uninstalled (status)
         && rc_package_is_installed (pkg))) {

        *slist = g_slist_prepend (*slist, rc_package_ref (pkg));
    } 
} /* prepend_pkg */

static void
prepend_pkg_pair (RCPackage *pkg_to_add,
                  RCPackageStatus status_to_add,
                  RCPackage *pkg_to_remove,
                  RCPackageStatus status_to_remove, 
                  gpointer user_data)
{
    GSList **slist = user_data;
    
    *slist = g_slist_prepend (*slist, rc_package_ref (pkg_to_add));

    /* We don't need to do the removal part of the upgrade */
} /* prepend_pkg_pair */

typedef enum {
    RCD_PACKAGE_OP_INSTALL,
    RCD_PACKAGE_OP_REMOVE
} RCDPackageOpType;

static const char *
rcd_package_op_type_to_string (RCDPackageOpType op_type)
{
    const char *type = NULL;

    switch (op_type) {
    case RCD_PACKAGE_OP_INSTALL:
        type = "install";
        break;
    case RCD_PACKAGE_OP_REMOVE:
        type = "remove";
        break;
    default:
        g_assert_not_reached ();
        break;
    }
    
    return type;
} /* rcd_package_op_type_to_string */

static void
dep_get_package_info_cb (RCResolverInfo *info, gpointer user_data)
{
    GSList **info_list = user_data;
    char *pkgs;
    char *info_str;

    switch (info->type) {
    case RC_RESOLVER_INFO_TYPE_NEEDED_BY:
        pkgs = rc_resolver_info_packages_to_string (info, FALSE);
        info_str = g_strconcat ("needed by: ", pkgs, NULL);
        g_free (pkgs);
        break;

    case RC_RESOLVER_INFO_TYPE_CONFLICTS_WITH:
        pkgs = rc_resolver_info_packages_to_string (info, FALSE);
        info_str = g_strconcat ("conflicts with: ", pkgs, NULL);
        g_free (pkgs);
        break;
        
    case RC_RESOLVER_INFO_TYPE_OBSOLETES:
        pkgs = rc_resolver_info_packages_to_string (info, FALSE);
        info_str = g_strconcat ("replaces: ", pkgs, NULL);
        g_free (pkgs);
        break;

    case RC_RESOLVER_INFO_TYPE_DEPENDS_ON:
        pkgs = rc_resolver_info_packages_to_string (info, FALSE);
        info_str = g_strconcat ("depends on: ", pkgs, NULL);
        g_free (pkgs);
        break;

    default:
        info_str = rc_resolver_info_to_string (info);
        break;
    }

    *info_list = g_slist_append (*info_list, info_str);
} /* dep_get_package_info_cb */

static GSList *
dep_get_package_info (RCResolver *resolver, RCPackage *package)
{
    GSList *info = NULL;

    rc_resolver_context_foreach_info (resolver->best_context,
                                      package,
                                      RC_RESOLVER_INFO_PRIORITY_USER,
                                      dep_get_package_info_cb,
                                      &info);

    return info;
} /* dep_get_package_info */

static xmlrpc_value *
rcd_rc_package_slist_to_xmlrpc_op_array (RCPackageSList   *packages,
                                         RCDPackageOpType  op_type,
                                         RCResolver       *resolver,
                                         xmlrpc_env       *env)
{
    RCPackageSList *iter;
    xmlrpc_value *array = NULL;

    array = xmlrpc_build_value (env, "()");
    XMLRPC_FAIL_IF_FAULT (env);

    for (iter = packages; iter; iter = iter->next) {
        RCPackage *package = iter->data;
        xmlrpc_value *op;
        xmlrpc_value *member;
        GSList *infos;

        op = xmlrpc_struct_new (env);
        XMLRPC_FAIL_IF_FAULT (env);

        RCD_XMLRPC_STRUCT_SET_STRING (
            env, op, "operation",
            rcd_package_op_type_to_string (op_type));

        member = rcd_rc_package_to_xmlrpc (package, env);
        XMLRPC_FAIL_IF_FAULT (env);
        xmlrpc_struct_set_value (env, op, "package", member);
        XMLRPC_FAIL_IF_FAULT (env);
        xmlrpc_DECREF (member);

        infos = dep_get_package_info (resolver, package);
        if (infos) {
            GSList *i;

            member = xmlrpc_build_value (env, "()");
            XMLRPC_FAIL_IF_FAULT (env);

            for (i = infos; i; i = i->next) {
                char *str = i->data;
                xmlrpc_value *v;

                v = xmlrpc_build_value (env, "s", str);
                XMLRPC_FAIL_IF_FAULT (env);
                xmlrpc_array_append_item (env, member, v);
                XMLRPC_FAIL_IF_FAULT (env);

                g_free (str);
                xmlrpc_DECREF (v);
            }
            
            xmlrpc_struct_set_value (env, op, "details", member);
            XMLRPC_FAIL_IF_FAULT (env);
            xmlrpc_DECREF (member);

            g_slist_free (infos);
        }

        xmlrpc_array_append_item (env, array, op);
        XMLRPC_FAIL_IF_FAULT (env);
        xmlrpc_DECREF (op);
    }

cleanup:
    if (env->fault_occurred)
        return NULL;

    return array;
} /* rc_package_slist_to_xmlrpc_op_array */

static void
resolve_deps (xmlrpc_env         *env,
              xmlrpc_value      **packages_to_install,
              xmlrpc_value      **packages_to_remove,
              xmlrpc_value      **resolution_info,
              RCPackageDepSList  *extra_dep_list,
              gboolean            verification,
              RCWorld            *world)
{
    RCPackageSList *install_packages = NULL;
    RCPackageSList *remove_packages = NULL;
    RCPackageSList *extra_install_packages = NULL;
    RCPackageSList *extra_remove_packages = NULL;
    GHashTable *install_hash = NULL;
    GHashTable *remove_hash = NULL;
    RCResolver *resolver = NULL;
    RCPackageSList *iter;

    g_return_if_fail (packages_to_install);
    g_return_if_fail (packages_to_remove);

    if (*packages_to_install) {
        install_packages = rcd_xmlrpc_array_to_rc_package_slist (
            *packages_to_install, env,
            RCD_PACKAGE_FROM_FILE | RCD_PACKAGE_FROM_STREAMED_PACKAGE |
            RCD_PACKAGE_FROM_XMLRPC_PACKAGE);
        XMLRPC_FAIL_IF_FAULT (env);
    }

    if (*packages_to_remove) {
        remove_packages = rcd_xmlrpc_array_to_rc_package_slist (
            *packages_to_remove, env,
            RCD_PACKAGE_FROM_NAME | RCD_PACKAGE_FROM_XMLRPC_PACKAGE);
        XMLRPC_FAIL_IF_FAULT (env);
    }

    resolver = rc_resolver_new ();

    rc_resolver_add_packages_to_install_from_slist (
        resolver, install_packages);
    rc_resolver_add_packages_to_remove_from_slist (
        resolver, remove_packages);

    for (iter = extra_dep_list; iter; iter = iter->next) {
        RCPackageDep *dep = iter->data;

        rc_resolver_add_extra_dependency (resolver, dep);
    }

    if (verification)
        rc_resolver_verify_system (resolver);
    else
        rc_resolver_resolve_dependencies (resolver);

    if (resolution_info) {
        RCResolverContext *info_context = NULL;

        if (resolver->best_context)
            info_context = resolver->best_context;
        else {
            RCResolverQueue *queue = resolver->invalid_queues->data;
            info_context = queue->context;
        }

        if (info_context) {
            *resolution_info = rcd_rc_resolver_context_info_to_xmlrpc_array (info_context,
                                                                             NULL, -1,
                                                                             env);
        }
    }

    if (!resolver->best_context) {
        char *dep_failure_info;

        dep_failure_info = dep_get_failure_info (resolver);
        xmlrpc_env_set_fault (env, RCD_RPC_FAULT_FAILED_DEPENDENCIES,
                              dep_failure_info);
        g_free (dep_failure_info);
        goto cleanup;
    }

    rc_resolver_context_foreach_install(
        resolver->best_context, prepend_pkg, &extra_install_packages);
    rc_resolver_context_foreach_uninstall(
        resolver->best_context, prepend_pkg, &extra_remove_packages);
    rc_resolver_context_foreach_upgrade(
        resolver->best_context, prepend_pkg_pair, &extra_install_packages);

    /* We need to remove any packages from the extra_*_packages lists
       that already appear in the *_packages list. To do this, we
       build up hashes containing the packages from the original lists
       and walk over the extra_ packages lists, removing anything that
       we've seen before. */

    install_hash = g_hash_table_new (rc_package_spec_hash,
                                     rc_package_spec_equal);
    for (iter = install_packages; iter != NULL; iter = iter->next)
        g_hash_table_insert (install_hash, iter->data, iter->data);
    
    remove_hash = g_hash_table_new (rc_package_spec_hash,
                                    rc_package_spec_equal);
    for (iter = remove_packages; iter != NULL; iter = iter->next)
        g_hash_table_insert (remove_hash, iter->data, iter->data);
    
    iter = extra_install_packages;
    while (iter != NULL) {
        GSList *next = iter->next;
        if (g_hash_table_lookup (install_hash, iter->data)) {
            rc_package_unref (iter->data);
            extra_install_packages = g_slist_delete_link (extra_install_packages, iter);
        }
        iter = next;
    }

    iter = extra_remove_packages;
    while (iter != NULL) {
        GSList *next = iter->next;
        if (g_hash_table_lookup (remove_hash, iter->data)) {
            rc_package_unref (iter->data);
            extra_remove_packages = g_slist_delete_link (extra_remove_packages, iter);
        }
        iter = next;
    }
    
    *packages_to_install = rcd_rc_package_slist_to_xmlrpc_op_array (
        extra_install_packages, RCD_PACKAGE_OP_INSTALL, resolver, env);
    XMLRPC_FAIL_IF_FAULT(env);

    *packages_to_remove = rcd_rc_package_slist_to_xmlrpc_op_array (
        extra_remove_packages, RCD_PACKAGE_OP_REMOVE, resolver, env);
    XMLRPC_FAIL_IF_FAULT(env);

cleanup:
    if (resolver)
        rc_resolver_free(resolver);

    rc_package_slist_unref (install_packages);
    rc_package_slist_unref (remove_packages);
    rc_package_slist_unref (extra_install_packages);
    rc_package_slist_unref (extra_remove_packages);

    if (install_hash)
        g_hash_table_destroy (install_hash);
    if (remove_hash)
        g_hash_table_destroy (remove_hash);
} /* resolve_deps */

static xmlrpc_value *
packsys_resolve_dependencies(xmlrpc_env   *env,
                             xmlrpc_value *param_array,
                             void         *user_data)
{
    RCWorld *world = (RCWorld *) user_data;
    xmlrpc_value *xmlrpc_install_packages;
    xmlrpc_value *xmlrpc_remove_packages;
    xmlrpc_value *xmlrpc_extra_deps;
    xmlrpc_value *xmlrpc_resolution_info;
    RCPackageDepSList *extra_dep_list;
    xmlrpc_value *value = NULL;

    xmlrpc_parse_value(
        env, param_array, "(AAA)",
        &xmlrpc_install_packages, &xmlrpc_remove_packages,
        &xmlrpc_extra_deps);
    XMLRPC_FAIL_IF_FAULT(env);

    extra_dep_list = rcd_xmlrpc_array_to_rc_package_dep_slist (
        xmlrpc_extra_deps, env);
    XMLRPC_FAIL_IF_FAULT (env);

    resolve_deps (env, &xmlrpc_install_packages, &xmlrpc_remove_packages,
                  &xmlrpc_resolution_info,
                  extra_dep_list, FALSE, world);
    rc_package_dep_slist_free (extra_dep_list);
    XMLRPC_FAIL_IF_FAULT (env);

    value = xmlrpc_build_value(env, "(VVV)",
                               xmlrpc_install_packages,
                               xmlrpc_remove_packages,
                               xmlrpc_resolution_info);
    XMLRPC_FAIL_IF_FAULT(env);

    xmlrpc_DECREF (xmlrpc_install_packages);
    xmlrpc_DECREF (xmlrpc_remove_packages);
    xmlrpc_DECREF (xmlrpc_resolution_info);

cleanup:
    return value;
} /* packsys_resolve_dependencies */

static xmlrpc_value *
packsys_verify_dependencies(xmlrpc_env   *env,
                            xmlrpc_value *param_array,
                            void         *user_data)
{
    RCWorld *world = (RCWorld *) user_data;
    xmlrpc_value *xmlrpc_install_packages = NULL;
    xmlrpc_value *xmlrpc_remove_packages = NULL;
    xmlrpc_value *xmlrpc_resolution_info;
    xmlrpc_value *value = NULL;

    resolve_deps (env, &xmlrpc_install_packages, &xmlrpc_remove_packages,
                  &xmlrpc_resolution_info,
                  NULL, TRUE, world);
    XMLRPC_FAIL_IF_FAULT (env);

    value = xmlrpc_build_value(env, "(VVV)",
                               xmlrpc_install_packages,
                               xmlrpc_remove_packages,
                               xmlrpc_resolution_info);
    XMLRPC_FAIL_IF_FAULT(env);

    xmlrpc_DECREF (xmlrpc_install_packages);
    xmlrpc_DECREF (xmlrpc_remove_packages);
    xmlrpc_DECREF (xmlrpc_resolution_info);

cleanup:
    return value;
} /* packsys_verify_dependencies */

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static xmlrpc_value *
parse_rollback_package_array (xmlrpc_value *package_names, xmlrpc_env *env)
{
    xmlrpc_value *package_list = NULL;
    int size;
    int i;

    size = xmlrpc_array_size (env, package_names);
    XMLRPC_FAIL_IF_FAULT (env);

    package_list = xmlrpc_build_value (env, "()");
    XMLRPC_FAIL_IF_FAULT (env);

    for (i = 0; i < size; i++) {
        xmlrpc_value *v;
        char *package_name;
        RCPackage *package;
        xmlrpc_value *xmlrpc_package;
        xmlrpc_value *xmlrpc_package_filename;

        v = xmlrpc_array_get_item (env, package_names, i);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_parse_value (env, v, "s", &package_name);
        XMLRPC_FAIL_IF_FAULT (env);

        package = rcd_rollback_get_package_by_name (package_name);

        if (!package) {
            xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PACKAGE_NOT_FOUND,
                                  "No rollback package found by name name");
            goto cleanup;
        }

        xmlrpc_package = rcd_rc_package_to_xmlrpc (package, env);
        XMLRPC_FAIL_IF_FAULT (env);

        /* We need to set the package_filename key manually */
        xmlrpc_package_filename = xmlrpc_build_value (
            env, "s", package->package_filename);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_struct_set_value (env, xmlrpc_package, "package_filename",
                                 xmlrpc_package_filename);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_DECREF (xmlrpc_package_filename);

        xmlrpc_array_append_item (env, package_list, xmlrpc_package);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_DECREF (xmlrpc_package);
    }

cleanup:
    if (env->fault_occurred) {
        if (package_list)
            xmlrpc_DECREF (package_list);

        return NULL;
    }

    return package_list;
} /* parse_rollback_package_array */

static xmlrpc_value *
packsys_rollback_dependencies(xmlrpc_env   *env,
                              xmlrpc_value *param_array,
                              void         *user_data)
{
    RCWorld *world = (RCWorld *) user_data;
    RCChannel *rollback_channel = NULL;
    GSList *iter;
    xmlrpc_value *xmlrpc_package_names;
    xmlrpc_value *xmlrpc_packages = NULL;
    xmlrpc_value *xmlrpc_installs = NULL;
    xmlrpc_value *xmlrpc_removals = NULL;
    xmlrpc_value *xmlrpc_extra_deps = NULL;
    xmlrpc_value *tmp;
    xmlrpc_value *result = NULL;

    xmlrpc_parse_value (env, param_array, "(A)", &xmlrpc_package_names);
    XMLRPC_FAIL_IF_FAULT (env);

    xmlrpc_packages = parse_rollback_package_array (xmlrpc_package_names, env);
    XMLRPC_FAIL_IF_FAULT (env);

    xmlrpc_installs = rcd_xmlrpc_array_copy (env, 1, xmlrpc_packages);
    XMLRPC_FAIL_IF_FAULT (env);

    /* Create a dummy channel with all the rollback packages. */
    rollback_channel = rc_world_add_channel (world,
                                             "Rollback Packages",
                                             "rollback-packages",
                                             0, 0,
                                             RC_CHANNEL_TYPE_UNKNOWN);

    for (iter = rcd_rollback_get_packages (); iter; iter = iter->next) {
        RCPackage *package = iter->data;

        package->channel = rc_channel_ref (rollback_channel);
        rc_world_add_package (world, package);
    }

    resolve_deps (
        env, &xmlrpc_installs, &xmlrpc_removals, &xmlrpc_extra_deps,
        NULL, FALSE, world);
    XMLRPC_FAIL_IF_FAULT (env);

    tmp = xmlrpc_packages;
    xmlrpc_packages = rcd_xmlrpc_array_copy (env, 2, tmp, xmlrpc_installs);
    xmlrpc_DECREF (tmp);

    result = xmlrpc_build_value (env, "(VVV)",
                                 xmlrpc_packages,
                                 xmlrpc_removals,
                                 xmlrpc_extra_deps);
    XMLRPC_FAIL_IF_FAULT (env);

cleanup:
    if (xmlrpc_packages)
        xmlrpc_DECREF (xmlrpc_packages);

    if (xmlrpc_installs)
        xmlrpc_DECREF (xmlrpc_installs);

    if (xmlrpc_removals)
        xmlrpc_DECREF (xmlrpc_removals);

    if (xmlrpc_extra_deps)
        xmlrpc_DECREF (xmlrpc_extra_deps);

    if (rollback_channel)
        rc_world_remove_channel (world, rollback_channel);
    
    if (env->fault_occurred)
        return NULL;

    return result;
} /* packsys_rollback_dependencies */

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static xmlrpc_value *
packsys_get_rollback_packages (xmlrpc_env   *env,
                               xmlrpc_value *param_array,
                               void         *user_data)
{
    xmlrpc_value *result;

    result = rcd_rc_package_slist_to_xmlrpc_array (
        rcd_rollback_get_packages (), env);

    if (env->fault_occurred)
        return NULL;

    return result;
} /* packsys_get_rollback_packages */

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

struct WhatProvidesInfo {
    xmlrpc_env *env;
    xmlrpc_value *array;
};

static void
what_provides_cb (RCPackage *pkg,
                  RCPackageSpec *spec,
                  gpointer user_data)
{
    struct WhatProvidesInfo *info = user_data;
    xmlrpc_value *pkg_value;
    xmlrpc_value *spec_value;
    xmlrpc_value *pkg_spec_pair;

    if (info->env->fault_occurred)
        return;

    pkg_value = rcd_rc_package_to_xmlrpc (pkg, info->env);

    spec_value = xmlrpc_struct_new (info->env);
    rcd_rc_package_spec_to_xmlrpc (spec, spec_value, info->env);

    pkg_spec_pair = xmlrpc_build_value (info->env, "(VV)", pkg_value, spec_value);
    XMLRPC_FAIL_IF_FAULT (info->env);

    xmlrpc_array_append_item (info->env, info->array, pkg_spec_pair);
    XMLRPC_FAIL_IF_FAULT (info->env);

 cleanup:
    xmlrpc_DECREF (pkg_value);
    xmlrpc_DECREF (spec_value);
    xmlrpc_DECREF (pkg_spec_pair);
}

static xmlrpc_value *
packsys_what_provides (xmlrpc_env   *env,
                       xmlrpc_value *param_array,
                       void         *user_data)
{
    RCWorld *world = (RCWorld *) user_data;
    struct WhatProvidesInfo info;
    xmlrpc_value *dep_value;
    RCPackageDep *dep;

    info.array = NULL;

    XMLRPC_FAIL_IF_FAULT (env);

    xmlrpc_parse_value (env, param_array, "(V)", &dep_value);
    XMLRPC_FAIL_IF_FAULT (env);

    dep = rcd_xmlrpc_to_rc_package_dep (dep_value, env);
    XMLRPC_FAIL_IF_FAULT (env);

    if (dep != NULL) {

        info.env = env;
        info.array = xmlrpc_build_value (env, "()");
        XMLRPC_FAIL_IF_FAULT (env);

        rc_world_foreach_providing_package (world,
                                            dep,
                                            RC_WORLD_ANY_CHANNEL,
                                            what_provides_cb,
                                            &info);

        rc_package_dep_unref (dep);
    }

 cleanup:

    return info.array;
}

struct WhatRequiresOrConflictsInfo {
    xmlrpc_env *env;
    xmlrpc_value *array;
};

static void
what_requires_or_conflicts_cb (RCPackage    *pkg,
                               RCPackageDep *dep,
                               gpointer      user_data)
{
    struct WhatRequiresOrConflictsInfo *info = user_data;
    xmlrpc_value *pkg_value;
    xmlrpc_value *dep_value;
    xmlrpc_value *pkg_dep_pair;

    if (info->env->fault_occurred)
        return;

    pkg_value = rcd_rc_package_to_xmlrpc (pkg, info->env);

    dep_value = xmlrpc_struct_new (info->env);
    rcd_rc_package_dep_to_xmlrpc (dep, dep_value, info->env);

    pkg_dep_pair = xmlrpc_build_value (info->env, "(VV)", pkg_value, dep_value);
    XMLRPC_FAIL_IF_FAULT (info->env);

    xmlrpc_array_append_item (info->env, info->array, pkg_dep_pair);
    XMLRPC_FAIL_IF_FAULT (info->env);

 cleanup:
    xmlrpc_DECREF (pkg_value);
    xmlrpc_DECREF (dep_value);
    xmlrpc_DECREF (pkg_dep_pair);
}

static xmlrpc_value *
packsys_what_requires (xmlrpc_env   *env,
                       xmlrpc_value *param_array,
                       void         *user_data)
{
    RCWorld *world = user_data;
    struct WhatRequiresOrConflictsInfo info;
    xmlrpc_value *dep_value;
    RCPackageDep *dep;

    info.array = NULL;

    xmlrpc_parse_value (env, param_array, "(V)", &dep_value);
    XMLRPC_FAIL_IF_FAULT (env);
    
    dep = rcd_xmlrpc_to_rc_package_dep (dep_value, env);
    XMLRPC_FAIL_IF_FAULT (env);

    if (dep != NULL) {

        info.env = env;
        info.array = xmlrpc_build_value (env, "()");
        XMLRPC_FAIL_IF_FAULT (env);

        rc_world_foreach_requiring_package (world,
                                            dep,
                                            RC_WORLD_ANY_CHANNEL,
                                            what_requires_or_conflicts_cb,
                                            &info);

        rc_package_dep_unref (dep);
    }

 cleanup:
    return info.array;
}

static xmlrpc_value *
packsys_what_conflicts (xmlrpc_env   *env,
                        xmlrpc_value *param_array,
                        void         *user_data)
{
    RCWorld *world = user_data;
    struct WhatRequiresOrConflictsInfo info;
    xmlrpc_value *dep_value;
    RCPackageDep *dep;

    info.array = NULL;

    xmlrpc_parse_value (env, param_array, "(V)", &dep_value);
    XMLRPC_FAIL_IF_FAULT (env);
    
    dep = rcd_xmlrpc_to_rc_package_dep (dep_value, env);
    XMLRPC_FAIL_IF_FAULT (env);

    if (dep != NULL) {

        info.env = env;
        info.array = xmlrpc_build_value (env, "()");
        XMLRPC_FAIL_IF_FAULT (env);

        rc_world_foreach_conflicting_package (world,
                                              dep,
                                              RC_WORLD_ANY_CHANNEL,
                                              what_requires_or_conflicts_cb,
                                              &info);

        rc_package_dep_unref (dep);
    }

 cleanup:
    return info.array;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

struct GetLocksInfo {
    xmlrpc_env *env;
    xmlrpc_value *array;
};

static void
get_lock_cb (RCPackageMatch *match,
             gpointer        user_data)
{
    struct GetLocksInfo *info = user_data;
    xmlrpc_value *match_value;

    match_value = rcd_rc_package_match_to_xmlrpc (match,
                                                  info->env);
    
    xmlrpc_array_append_item (info->env, info->array, match_value);
}

static xmlrpc_value *
packsys_get_locks (xmlrpc_env   *env,
                   xmlrpc_value *param_array,
                   void         *user_data)
{
    RCWorld *world = user_data;
    struct GetLocksInfo info;

    info.env = env;
    info.array = xmlrpc_build_value (env, "()");
    XMLRPC_FAIL_IF_FAULT (env);

    rc_world_foreach_lock (world,
                           get_lock_cb,
                           &info);

 cleanup:
    return info.array;
}

static xmlrpc_value *
packsys_add_lock (xmlrpc_env   *env,
                  xmlrpc_value *param_array,
                  void         *user_data)
{
    RCWorld *world = user_data;
    xmlrpc_value *match_value;
    RCPackageMatch *match;
    gboolean success = FALSE;

    xmlrpc_parse_value(env, param_array, "(V)", &match_value);
    XMLRPC_FAIL_IF_FAULT (env);

    match = rcd_xmlrpc_to_rc_package_match (match_value, env);
    if (match) {
        rc_world_add_lock (world, match);
        rcd_package_locks_save (world);
        success = TRUE;
    }

 cleanup:
    return xmlrpc_build_value (env, "i", success);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static xmlNode *
extra_dump_info (void)
{
    xmlNode *info;
    time_t now;
    char *tmp_str;
    struct utsname uname_buf;
    xmlNode *distro_node;

    info = xmlNewNode (NULL, "general_information");

    xmlNewTextChild (info, NULL, "rcd_version", VERSION);

    distro_node = xmlNewNode (NULL, "distro");
    xmlAddChild (info, distro_node);
    xmlNewTextChild (distro_node, NULL, "name",
                     rc_distro_get_name ());
    xmlNewTextChild (distro_node, NULL, "version",
                     rc_distro_get_version ());
    xmlNewTextChild (distro_node, NULL, "target",
                     rc_distro_get_target ());

    time (&now);
    xmlNewTextChild (info, NULL, "time", ctime (&now));

    tmp_str = getenv ("LOGNAME");
    if (tmp_str)
        xmlNewTextChild (info, NULL, "logname", tmp_str);

    if (uname (&uname_buf) == 0) {
        xmlNewTextChild (info, NULL, "nodename", uname_buf.nodename);
        xmlNewTextChild (info, NULL, "sysname", uname_buf.sysname);
        xmlNewTextChild (info, NULL, "release", uname_buf.release);
        xmlNewTextChild (info, NULL, "version", uname_buf.version);
        xmlNewTextChild (info, NULL, "machine", uname_buf.machine);
#ifdef GNU_SOURCE
        xmlNewTextChild (info, NULL, "domainname", uname_buf.domainname);
#endif
    }

    xmlNewTextChild (info, NULL, "host", rcd_prefs_get_host ());
    xmlNewTextChild (info, NULL, "premium",
                     rcd_prefs_get_premium () ? "1" : "0");
    xmlNewTextChild (info, NULL, "proxy", rcd_prefs_get_proxy ());

    return info;

}

static xmlrpc_value *
packsys_dump(xmlrpc_env   *env,
             xmlrpc_value *param_array,
             void         *user_data)
{
    RCWorld *world = (RCWorld *) user_data;
    char *xml;
    GByteArray *ba;
    xmlrpc_value *value = NULL;

    xml = rc_world_dump (world, extra_dump_info ());
    rc_compress_memory (xml, strlen (xml), &ba);
    g_free (xml);

    value = xmlrpc_build_value (env, "6", ba->data, ba->len);
    g_byte_array_free (ba, TRUE);

    return value;
} /* packsys_dump */

static xmlrpc_value *
packsys_mount_directory(xmlrpc_env   *env,
                        xmlrpc_value *param_array,
                        void         *user_data)
{
    RCWorld *world = (RCWorld *) user_data;
    RCChannel *channel = NULL;
    char *path, *name, *alias;
    xmlrpc_value *retval;

    xmlrpc_parse_value (env, param_array, "(sss)",
                        &path, &name, &alias);

    if (g_file_test (path, G_FILE_TEST_IS_DIR)) {
        channel = rc_world_add_channel_from_directory (world,
                                                       name, alias,
                                                       path);
    }

    retval = xmlrpc_build_value (env, "i", 
                                 channel ? rc_channel_get_id (channel) : 0);
    return retval;
}

static xmlrpc_value *
packsys_unmount_directory(xmlrpc_env   *env,
                          xmlrpc_value *param_array,
                          void         *user_data)
{
    RCWorld *world = user_data;
    RCChannel *channel = NULL;
    gint cid;
    xmlrpc_value *retval;

    retval = xmlrpc_build_value (env, "i", 0);
    XMLRPC_FAIL_IF_FAULT (env);

    xmlrpc_parse_value (env, param_array, "(i)", &cid);
    XMLRPC_FAIL_IF_FAULT (env);

    channel = rc_world_get_channel_by_id (world, cid);
    if (channel == NULL)
        goto cleanup;

    /* OK, this is sort of a hack.  We only want to allow the user to
       remove directory-mounted channels, so we only allow the unmount
       to succeed if the selected channel:
       (0) actually exists (duh)
       (1) is transient
       (2) has refresh magic
       (3) has a description where the first character is '/'.
       This is sort of a hack, but should be good enough for 99.9% of
       all real-life cases. */

    if (channel
        && rc_channel_get_transient (channel)
        && rc_channel_has_refresh_magic (channel)) {
        const char *desc = rc_channel_get_description (channel);
        if (desc && *desc == '/') {
            rc_world_remove_channel (world, channel);
            xmlrpc_DECREF (retval);
            retval = xmlrpc_build_value (env, "i", 1);
        }
    }
    
 cleanup:
    return retval;
}

static xmlrpc_value *
packsys_world_sequence_numbers (xmlrpc_env   *env,
                                xmlrpc_value *param_array,
                                void         *user_data)
{
    RCWorld *world = user_data;
    xmlrpc_value *value;

    value = xmlrpc_build_value (env, "(iii)",
                                rc_world_get_package_sequence_number (world),
                                rc_world_get_channel_sequence_number (world),
                                rc_world_get_subscription_sequence_number (world));

    return value;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

void
rcd_rpc_packsys_register_methods(RCWorld *world)
{
    rcd_rpc_register_method("rcd.packsys.search",
                            packsys_search,
                            "view",
                            world);

    rcd_rpc_register_method("rcd.packsys.query_file",
                            packsys_query_file,
                            "view",
                            world);

    rcd_rpc_register_method("rcd.packsys.find_latest_version",
                            packsys_find_latest_version,
                            "view",
                            world);

    rcd_rpc_register_method("rcd.packsys.package_info",
                            packsys_package_info,
                            "view",
                            world);

    rcd_rpc_register_method("rcd.packsys.package_dependency_info",
                            packsys_package_dependency_info,
                            "view",
                            world);
    
    rcd_rpc_register_method("rcd.packsys.get_updates",
                            packsys_get_updates,
                            "view",
                            world);

    rcd_rpc_register_method("rcd.packsys.update_summary",
                            packsys_update_summary,
                            "view",
                            world);

    rcd_rpc_register_method("rcd.packsys.resolve_dependencies",
                            packsys_resolve_dependencies,
                            "view",
                            world);

    rcd_rpc_register_method("rcd.packsys.verify_dependencies",
                            packsys_verify_dependencies,
                            "view",
                            world);

    rcd_rpc_register_method("rcd.packsys.rollback_dependencies",
                            packsys_rollback_dependencies,
                            "view",
                            world);

    rcd_rpc_register_method("rcd.packsys.get_rollback_packages",
                            packsys_get_rollback_packages,
                            "view",
                            world);

    rcd_rpc_register_method("rcd.packsys.transact",
                            packsys_transact,
                            "",
                            world);

    rcd_rpc_register_method("rcd.packsys.abort_download",
                            packsys_abort_download,
                            "",
                            world);

    rcd_rpc_register_method("rcd.packsys.what_provides",
                            packsys_what_provides,
                            "view",
                            world);

    rcd_rpc_register_method("rcd.packsys.what_requires",
                            packsys_what_requires,
                            "view",
                            world);

    rcd_rpc_register_method("rcd.packsys.what_conflicts",
                            packsys_what_conflicts,
                            "view",
                            world);

    rcd_rpc_register_method("rcd.packsys.get_locks",
                            packsys_get_locks,
                            "view",
                            world);

    rcd_rpc_register_method("rcd.packsys.add_lock",
                            packsys_add_lock,
                            "subscribe", /* FIXME */
                            world);

    rcd_rpc_register_method("rcd.packsys.dump",
                            packsys_dump,
                            "view",
                            world);

    rcd_rpc_register_method("rcd.packsys.get_channels",
                            packsys_get_channels,
                            "view",
                            world);

    rcd_rpc_register_method("rcd.packsys.refresh_channel",
                            packsys_refresh_channel,
                            "view",
                            world);

    rcd_rpc_register_method("rcd.packsys.refresh_all_channels",
                            packsys_refresh_all_channels,
                            "view",
                            world);

    rcd_rpc_register_method("rcd.packsys.get_channel_icon",
                            packsys_get_channel_icon,
                            "view",
                            world);

    rcd_rpc_register_method("rcd.packsys.subscribe",
                            packsys_subscribe,
                            "subscribe",
                            world);

    rcd_rpc_register_method("rcd.packsys.unsubscribe",
                            packsys_unsubscribe,
                            "subscribe",
                            world);

    rcd_rpc_register_method("rcd.packsys.mount_directory",
                            packsys_mount_directory,
                            "superuser",
                            world);

    rcd_rpc_register_method("rcd.packsys.unmount_directory",
                            packsys_unmount_directory,
                            "superuser",
                            world);

    rcd_rpc_register_method("rcd.packsys.world_sequence_numbers",
                            packsys_world_sequence_numbers,
                            "view",
                            world);

    rcd_heartbeat_register_func (refresh_channels_cb, NULL);
} /* rcd_rpc_packsys_register_methods */

