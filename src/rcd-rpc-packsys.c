/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include <config.h>
#include "rcd-rpc-packsys.h"

#include <unistd.h>

#include <xmlrpc.h>

#include "rcd-log.h"

#include "rcd-fetch.h"
#include "rcd-heartbeat.h"
#include "rcd-pending.h"
#include "rcd-prefs.h"
#include "rcd-query-packages.h"
#include "rcd-rpc.h"
#include "rcd-rpc-util.h"
#include "rcd-subscriptions.h"

static gboolean packsys_lock = FALSE;

typedef struct {
    RCPackman *packman;

    RCPackageSList *install_packages;
    RCPackageSList *remove_packages;

    RCPackageSList *packages_to_download;

    RCDPending *pending;

    gsize total_download_size;
    gsize current_download_size;

    int total_transaction_steps;
} RCDTransactionStatus;

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
    }

    value = xmlrpc_build_value (env, "i", pending_id);

 cleanup:
    if (env->fault_occurred)
        return NULL;

    return value;
}

static void
remove_channel_cb (RCChannel *channel, gpointer user_data)
{
    rc_world_remove_channel (rc_get_world (), channel);
} /* remove_channel_cb */

static void
refresh_channels_cb (gpointer user_data)
{
    if (packsys_lock) {
        rc_debug (RC_DEBUG_LEVEL_MESSAGE, 
                  "Can't refresh channel data while transaction is running");
        return;
    }

    rc_world_foreach_channel (rc_get_world (), remove_channel_cb, NULL);

    rcd_fetch_channel_list ();
    rcd_subscriptions_load ();
    rcd_fetch_all_channels ();
} /* refresh_channels_cb */

static xmlrpc_value *
packsys_refresh_all_channels (xmlrpc_env   *env,
                              xmlrpc_value *param_array,
                              void         *user_data)
{
    xmlrpc_value *value;

    refresh_channels_cb (NULL);

    value = xmlrpc_build_value (env, "i", 0);

    return value;
} /* packsys_refresh_all_channels */

static xmlrpc_value *
packsys_subscribe (xmlrpc_env   *env,
                   xmlrpc_value *param_array,
                   void         *user_data)
{
    RCWorld *world = user_data;
    RCChannel *channel = NULL;
    xmlrpc_value *value = NULL;
    gint channel_id = -1;

    xmlrpc_parse_value (env, param_array, "(i)", &channel_id);
    XMLRPC_FAIL_IF_FAULT (env);

    channel = rc_world_get_channel_by_id (world, channel_id);
    if (channel != NULL && ! rc_channel_subscribed (channel)) {
        rc_channel_set_subscription (channel, TRUE);
        rcd_subscriptions_save ();
    }

    value = xmlrpc_build_value (env, "i", channel ? 1 : 0);

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

    xmlrpc_parse_value (env, param_array, "(i)", &channel_id);
    XMLRPC_FAIL_IF_FAULT (env);

    channel = rc_world_get_channel_by_id (world, channel_id);
    if (channel != NULL && rc_channel_subscribed (channel)) {
        rc_channel_set_subscription (channel, FALSE);
        rcd_subscriptions_save ();
    }

    value = xmlrpc_build_value (env, "i", channel ? 1 : 0);

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

#if 0
    /* Bogus test logging */
    {
        RCDLogEntry *foo = rcd_log_entry_new ("foo", "bar");
        rcd_log_entry_set_upgrade (foo, old, nuevo);
        rcd_log (foo);
    }
#endif

    old_xmlrpc = rcd_rc_package_to_xmlrpc (old, info->env);
    new_xmlrpc = rcd_rc_package_to_xmlrpc (nuevo, info->env);

    history = xmlrpc_build_value (info->env, "()");
    XMLRPC_FAIL_IF_FAULT (info->env);

    iter = nuevo->history;
    while (iter != NULL) {

        RCPackageUpdate *update = iter->data;

        if (rc_package_spec_compare (&old->spec, &update->spec) < 0) {
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
            xmlrpc_env_set_fault (env, -604, "Invalid search type");
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
        xmlrpc_env_set_fault(env, -601, "Couldn't get package from file");
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
} LatestVersionClosure;

static void
find_latest_version (RCPackage *package, gpointer user_data)
{
    LatestVersionClosure *closure = user_data;
    RCPackman *packman = rc_world_get_packman (closure->world);

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

static xmlrpc_value *
packsys_find_latest_version (xmlrpc_env   *env,
                             xmlrpc_value *param_array,
                             void         *user_data)
{
    RCWorld *world = (RCWorld *) user_data;
    char *name;
    LatestVersionClosure closure;
    xmlrpc_value *result = NULL;

    xmlrpc_parse_value (env, param_array, "(s)", &name);
    XMLRPC_FAIL_IF_FAULT (env);

    closure.world = world;
    closure.package = NULL;
    rc_world_foreach_package_by_name (
        world, name, RC_WORLD_ANY_NON_SYSTEM, find_latest_version, &closure);

    if (!closure.package) {
        xmlrpc_env_set_fault(env, -601, "Couldn't get package from file");
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

        RCD_XMLRPC_STRUCT_SET_INT (
            env, result, "installed_size", package->installed_size);

        RCD_XMLRPC_STRUCT_SET_STRING (
            env, result, "summary", package->summary);
                                   
        RCD_XMLRPC_STRUCT_SET_STRING (
            env, result, "description", package->description);
    }
    else {
        xmlrpc_env_set_fault(env, -601, "Couldn't get package");
        return NULL;
    }
    
cleanup:
    return result;
} /* packsys_package_info */

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static void
transact_start_cb(RCPackman *packman,
                  int total_steps,
                  RCDTransactionStatus *status)
{
    rc_debug (RC_DEBUG_LEVEL_MESSAGE,
              "Transaction starting.  %d steps", total_steps);

    status->total_transaction_steps = total_steps;
} /* transact_start_cb */

static void
transact_step_cb(RCPackman *packman,
                 int seqno,
                 RCPackmanStep step,
                 char *name,
                 RCDTransactionStatus *status)
{
    char *action = NULL;
    char *msg;

    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Transaction step.  seqno %d", seqno);

    switch (step) {
    case RC_PACKMAN_STEP_UNKNOWN:
    case RC_PACKMAN_STEP_PREPARE:
        action = "prepare";
        break;
    case RC_PACKMAN_STEP_INSTALL:
        action = "install";
        break;
    case RC_PACKMAN_STEP_REMOVE:
        action = "remove";
        break;
    case RC_PACKMAN_STEP_CONFIGURE:
        action = "configure";
        break;
    default:
        g_assert_not_reached ();
        break;
    }

    if (name)
        msg = g_strconcat (action, ":", name, NULL);
    else
        msg = g_strdup (action);

    rcd_pending_add_message (status->pending, msg);
    g_free (msg);
} /* transact_step_cb */

static void
transact_progress_cb(RCPackman *packman,
                     int amount,
                     int total,
                     RCDTransactionStatus *status)
{
    rc_debug (RC_DEBUG_LEVEL_MESSAGE,
              "Transaction progress.  %d of %d", amount, total);
} /* transact_progress_cb */

static void
transact_done_cb(RCPackman *packman,
                 RCDTransactionStatus *status)
{
    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Transaction done");

    rcd_pending_add_message (status->pending, "finish");
    rcd_pending_finished (status->pending, 0);
} /* transact_done_cb */

static void
cleanup_temp_package_files (RCPackageSList *packages)
{
    RCPackageSList *iter;

    for (iter = packages; iter; iter = iter->next) {
        RCPackage *p = iter->data;

        unlink (p->package_filename);
        g_free (p->package_filename);
        p->package_filename = NULL;
    }
} /* cleanup_temp_package_files */

static gboolean
run_transaction(gpointer user_data)
{
    RCDTransactionStatus *status = user_data;

#if 0
    rcd_pending_add_message (status->pending, "transaction:beginning");
#endif

    packsys_lock = TRUE;

    g_signal_connect (
        G_OBJECT (status->packman), "transact_start",
        G_CALLBACK (transact_start_cb), status);
    g_signal_connect (
        G_OBJECT (status->packman), "transact_step",
        G_CALLBACK (transact_step_cb), status);
    g_signal_connect (
        G_OBJECT (status->packman), "transact_progress",
        G_CALLBACK (transact_progress_cb), status);
    g_signal_connect (
        G_OBJECT (status->packman), "transact_done",
        G_CALLBACK (transact_done_cb), status);

    rc_packman_transact (status->packman,
                         status->install_packages,
                         status->remove_packages);

    g_signal_handlers_disconnect_by_func (
        G_OBJECT (status->packman),
        G_CALLBACK (transact_done_cb), status);
    g_signal_handlers_disconnect_by_func (
        G_OBJECT (status->packman),
        G_CALLBACK (transact_start_cb), status);
    g_signal_handlers_disconnect_by_func (
        G_OBJECT (status->packman),
        G_CALLBACK (transact_step_cb), status);
    g_signal_handlers_disconnect_by_func (
        G_OBJECT (status->packman),
        G_CALLBACK (transact_progress_cb), status);

    if (rc_packman_get_error (status->packman)) {
        char *msg;

        rc_debug (RC_DEBUG_LEVEL_MESSAGE,
                  "packman error: %s",
                  rc_packman_get_reason (status->packman));

        msg = g_strdup_printf("failed:%s",
                              rc_packman_get_reason (status->packman));
        rcd_pending_add_message (status->pending, msg);
        g_free (msg);
        rcd_pending_fail (status->pending, -1,
                          rc_packman_get_reason (status->packman));
    }

    /*
     * If caching is turned off, we don't want to keep around the package
     * files on disk.
     */
    if (!rcd_prefs_get_cache_enabled ())
        cleanup_temp_package_files (status->packages_to_download);

    rc_world_get_system_packages (rc_get_world ());

    packsys_lock = FALSE;

    return FALSE;
} /* run_transaction */

static void
update_download_progress (gsize size, gpointer user_data)
{
    RCDTransactionStatus *status = user_data;
    double percent;

    status->current_download_size += size;

    percent = (double) ((double) status->current_download_size /
                        (double) status->total_download_size) * 100.0;

    rcd_pending_update (status->pending, percent);
} /* update_download_progress */

static gboolean
download_packages (RCPackageSList *packages, RCDTransactionStatus *status)
{
    RCPackageSList *iter;

    status->total_download_size = 0;
    status->packages_to_download = NULL;

    for (iter = packages; iter; iter = iter->next) {
        RCPackage *package = iter->data;

        if (!g_file_test (package->package_filename, G_FILE_TEST_EXISTS)) {
            g_free (package->package_filename);
            package->package_filename = NULL;
        }

        if (!package->package_filename) {
            status->packages_to_download = g_slist_prepend (
                status->packages_to_download, package);
            status->total_download_size +=
                rc_package_get_latest_update (package)->package_size;
        }
    }

    if (!status->packages_to_download)
        return FALSE;

    rcd_pending_add_message (status->pending, "download");
    rcd_pending_update (status->pending, 0.0);

    status->packages_to_download =
        g_slist_reverse (status->packages_to_download);

    rcd_fetch_packages (
        status->packages_to_download, 
        update_download_progress,
        run_transaction,
        status);

    return TRUE;
} /* download_packages */

static void
check_install_package_auth (xmlrpc_env     *env,
                            RCWorld        *world,
                            RCPackageSList *packages, 
                            RCDIdentity    *identity)
{
    RCPackageSList *iter;
    gboolean install = FALSE;
    gboolean upgrade = FALSE;
    RCDAuthActionList *req;
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
        req = rcd_auth_action_list_from_1 (RCD_AUTH_UPGRADE);
        approved = rcd_auth_approve_action (identity, req, NULL);
        g_slist_free(req);
    
        if (!approved) {
            xmlrpc_env_set_fault (env, -610, "Permission denied");
            rc_debug (RC_DEBUG_LEVEL_MESSAGE,
                      "Caller does not have permissions to upgrade packages");
        }
    }

    if (install) {
        req = rcd_auth_action_list_from_1 (RCD_AUTH_INSTALL);
        approved = rcd_auth_approve_action (identity, req, NULL);
        g_slist_free(req);
    
        if (!approved) {
            xmlrpc_env_set_fault (env, -610, "Permission denied");
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
    RCDAuthActionList *req;
    gboolean approved;

    if (!packages)
        return;

    req = rcd_auth_action_list_from_1 (RCD_AUTH_REMOVE);
    approved = rcd_auth_approve_action (identity, req, NULL);
    g_slist_free(req);
    
    if (!approved) {
        xmlrpc_env_set_fault (env, -610, "Permission denied");
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
    RCPackageSList *install_packages = NULL;
    RCPackageSList *remove_packages = NULL;
    RCDIdentity *identity;
    RCDTransactionStatus *status;
    xmlrpc_value *result = NULL;

    xmlrpc_parse_value(
        env, param_array, "(AA)",
        &xmlrpc_install_packages, &xmlrpc_remove_packages);
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

    if (getenv ("RCD_ENFORCE_AUTH")) {
        /* Check our permissions to install/upgrade/remove */
        identity = rcd_rpc_get_caller_identity ();
        
        check_install_package_auth (env, world, install_packages, identity);
        XMLRPC_FAIL_IF_FAULT (env);
        
        check_remove_package_auth (env, remove_packages, identity);
        XMLRPC_FAIL_IF_FAULT (env);
    }

    /* Track our transaction */
    status = g_new0(RCDTransactionStatus, 1);
    status->packman = rc_world_get_packman (world);
    status->install_packages = install_packages;
    status->remove_packages = remove_packages;
    status->pending = rcd_pending_new ("Beginning transaction");

    g_object_set_data (G_OBJECT (status->pending), "status", status);
    rcd_pending_begin (status->pending);

    rc_package_slist_ref(status->install_packages);
    rc_package_slist_ref(status->remove_packages);

    /*
     * If we have to download files, start the download.  Otherwise,
     * schedule the transaction
     */
    if (!download_packages (status->install_packages, status))
        g_idle_add (run_transaction, status);

    result = xmlrpc_build_value (env, "i",
                                 rcd_pending_get_id (status->pending));
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

#if 0
static void
prepend_pkg (RCPackage *pkg, RCPackageStatus status, gpointer user_data)
{
    RCPackageSList **package_list = user_data;

    *package_list = g_slist_prepend(*package_list, pkg);
} /* prepend_pkg */

static void
prepend_pkg_pair (RCPackage *pkg_to_add,
                  RCPackageStatus status_to_add,
                  RCPackage *pkg_to_remove,
                  RCPackageStatus status_to_remove, 
                  gpointer user_data)
{
    RCPackageSList **package_list = user_data;

    *package_list = g_slist_prepend(*package_list, pkg_to_add);

    /* We don't need to do the removal part of the upgrade */
}

static xmlrpc_value *
packman_resolve_dependencies(xmlrpc_env   *env,
                             xmlrpc_value *param_array,
                             void         *user_data)
{
    RCPackman *packman = (RCPackman *) user_data;
    xmlrpc_value *xmlrpc_install_packages;
    xmlrpc_value *xmlrpc_remove_packages;
    RCPackageSList *install_packages = NULL;
    RCPackageSList *remove_packages = NULL;
    RCResolver *resolver = NULL;
    xmlrpc_value *value;

    xmlrpc_parse_value(
        env, param_array, "(AA)",
        &xmlrpc_install_packages, &xmlrpc_remove_packages);
    XMLRPC_FAIL_IF_FAULT(env);

    install_packages = rcd_xmlrpc_parse_package_array(
        xmlrpc_install_packages, env);
    XMLRPC_FAIL_IF_FAULT(env);

    remove_packages = rcd_xmlrpc_parse_package_array(
        xmlrpc_remove_packages, env);
    XMLRPC_FAIL_IF_FAULT(env);

    resolver = rc_resolver_new();

    rc_resolver_add_packages_to_install_from_slist(resolver, install_packages);
    rc_resolver_add_packages_to_remove_from_slist(resolver, remove_packages);

    rc_package_slist_unref(install_packages);
    rc_package_slist_unref(remove_packages);

    install_packages = NULL;
    remove_packages = NULL;

    /* FIXME: Set current channel and subscribed channels here? */

    if (rc_packman_get_capabilities(packman) & 
        RC_PACKMAN_CAP_VIRTUAL_CONFLICTS)
        rc_resolver_allow_virtual_conflicts(resolver, TRUE);

    rc_resolver_resolve_dependencies(resolver);

    if (!resolver->best_context) {
        xmlrpc_env_set_fault(env, -604, "Unresolved dependencies");
        goto cleanup;
    }

    rc_resolver_context_foreach_install(
        resolver->best_context, prepend_pkg, &install_packages);
    rc_resolver_context_foreach_uninstall(
        resolver->best_context, prepend_pkg, &remove_packages);
    rc_resolver_context_foreach_upgrade(
        resolver->best_context, prepend_pkg_pair, &install_packages);

    xmlrpc_install_packages = rcd_xmlrpc_build_package_array(
        install_packages, env);
    XMLRPC_FAIL_IF_FAULT(env);

    xmlrpc_remove_packages = rcd_xmlrpc_build_package_array(
        remove_packages, env);
    XMLRPC_FAIL_IF_FAULT(env);

    value = xmlrpc_build_value(
        env, "(VV)", xmlrpc_install_packages, xmlrpc_remove_packages);
    XMLRPC_FAIL_IF_FAULT(env);

    xmlrpc_DECREF(xmlrpc_install_packages);
    xmlrpc_DECREF(xmlrpc_remove_packages);

cleanup:
    if (resolver)
        rc_resolver_free(resolver);

    if (env->fault_occurred)
        return NULL;

    return value;
} /* packman_resolve_dependencies */
#endif

void
rcd_rpc_packsys_register_methods(RCWorld *world)
{
    rcd_rpc_register_method("rcd.packsys.search",
                            packsys_search,
                            rcd_auth_action_list_from_1 (RCD_AUTH_VIEW),
                            world);

    rcd_rpc_register_method("rcd.packsys.query_file",
                            packsys_query_file,
                            rcd_auth_action_list_from_1 (RCD_AUTH_VIEW),
                            world);

    rcd_rpc_register_method("rcd.packsys.find_latest_version",
                            packsys_find_latest_version,
                            rcd_auth_action_list_from_1 (RCD_AUTH_VIEW),
                            world);

    rcd_rpc_register_method("rcd.packsys.package_info",
                            packsys_package_info,
                            rcd_auth_action_list_from_1 (RCD_AUTH_VIEW),
                            world);

    rcd_rpc_register_method("rcd.packsys.get_updates",
                            packsys_get_updates,
                            rcd_auth_action_list_from_1 (RCD_AUTH_VIEW),
                            world);

    rcd_rpc_register_method("rcd.packsys.transact",
                            packsys_transact,
                            rcd_auth_action_list_from_1 (RCD_AUTH_NONE),
                            world);

    rcd_rpc_register_method("rcd.packsys.get_channels",
                            packsys_get_channels,
                            rcd_auth_action_list_from_1 (RCD_AUTH_VIEW),
                            world);

    rcd_rpc_register_method("rcd.packsys.refresh_channel",
                            packsys_refresh_channel,
                            rcd_auth_action_list_from_1 (RCD_AUTH_VIEW),
                            world);

    rcd_rpc_register_method("rcd.packsys.refresh_all_channels",
                            packsys_refresh_all_channels,
                            rcd_auth_action_list_from_1 (RCD_AUTH_VIEW),
                            world);

    rcd_rpc_register_method("rcd.packsys.subscribe",
                            packsys_subscribe,
                            /* FIXME: what is the right auth to use here? */
                            rcd_auth_action_list_from_1 (RCD_AUTH_VIEW),
                            world);

    rcd_rpc_register_method("rcd.packsys.unsubscribe",
                            packsys_unsubscribe,
                            /* FIXME: what is the right auth to use here? */
                            rcd_auth_action_list_from_1 (RCD_AUTH_VIEW),
                            world);

    rcd_heartbeat_register_func (refresh_channels_cb, NULL);

#if 0
    rcd_rpc_register_method(
        "rcd.packsys.resolve_dependencies",
        packman_resolve_dependencies,
        packman);
#endif
} /* rcd_rpc_packsys_register_methods */

