/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include <config.h>
#include "rcd-rpc-packsys.h"

#include <unistd.h>

#include <xmlrpc.h>

#include "rcd-fetch.h"
#include "rcd-pending.h"
#include "rcd-query-packages.h"
#include "rcd-rpc.h"
#include "rcd-rpc-util.h"

typedef struct {
    RCPackman *packman;

    RCPackageSList *install_packages;
    RCPackageSList *remove_packages;

    RCDPending *pending;
    int total_steps;
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
add_package_cb (RCPackage *package, gpointer user_data)
{
    RCPackageSList **packages = (RCPackageSList **) user_data;

    *packages = g_slist_prepend(*packages, rc_package_ref (package));
} /* add_package_cb */

static xmlrpc_value *
packsys_query (xmlrpc_env   *env,
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
} /* packsys_query */

static xmlrpc_value *
packsys_query_file (xmlrpc_env   *env,
                    xmlrpc_value *param_array,
                    void         *user_data)
{
    RCWorld *world = (RCWorld *) user_data;
    RCPackman *packman;
    RCPackage *rc_package;
    xmlrpc_value *value;
    xmlrpc_value *xmlrpc_package = NULL;

    packman = rc_world_get_packman (world);

    xmlrpc_parse_value(env, param_array, "(V)", &value);
    XMLRPC_FAIL_IF_FAULT(env);

    rc_package = rcd_xmlrpc_streamed_to_rc_package(packman, value, env);
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

static void
transact_start_cb(RCPackman *packman,
                  int total_steps,
                  RCDTransactionStatus *status)
{
    rc_debug (RC_DEBUG_LEVEL_MESSAGE,
              "Transaction starting.  %d steps", total_steps);

    status->total_steps = total_steps;
    rcd_pending_begin (status->pending);
} /* transact_start_cb */

static void
transact_step_cb(RCPackman *packman,
                 int seqno,
                 RCPackmanStep step,
                 char *name,
                 RCDTransactionStatus *status)
{
    double percent;

    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Transaction step.  seqno %d", seqno);

    percent = (double) seqno / (double) status->total_steps * 100.0;

    rcd_pending_update (status->pending, percent);
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

    rcd_pending_finished (status->pending, 0);
} /* transact_done_cb */

static gboolean
run_transaction(gpointer data)
{
    RCDTransactionStatus *status = data;

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
        rc_debug (RC_DEBUG_LEVEL_MESSAGE,
                  "packman error: %s",
                  rc_packman_get_reason (status->packman));

        if (rcd_pending_get_status (status->pending) == 
            RCD_PENDING_STATUS_PRE_BEGIN)
            rcd_pending_begin (status->pending);

        rcd_pending_fail (status->pending, -1,
                          rc_packman_get_reason (status->packman));
    }

    return FALSE;
} /* run_transaction */

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
    RCPackman *packman;
    xmlrpc_value *xmlrpc_install_packages;
    xmlrpc_value *xmlrpc_remove_packages;
    RCPackageSList *install_packages = NULL;
    RCPackageSList *remove_packages = NULL;
    RCDIdentity *identity;
    RCDTransactionStatus *status;
    xmlrpc_value *result = NULL;

    packman = rc_world_get_packman (world);

    xmlrpc_parse_value(
        env, param_array, "(AA)",
        &xmlrpc_install_packages, &xmlrpc_remove_packages);
    XMLRPC_FAIL_IF_FAULT(env);

    install_packages = rcd_xmlrpc_streamed_array_to_rc_package_slist (
        packman, xmlrpc_install_packages, env);
    remove_packages = rcd_xmlrpc_streamed_array_to_rc_package_slist (
        packman, xmlrpc_remove_packages, env);

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
    status->packman = packman;
    status->install_packages = install_packages;
    status->remove_packages = remove_packages;
    status->pending = rcd_pending_new ("Transaction status");
    
    rcd_pending_set_user_data(status->pending, status);

    rc_package_slist_ref(status->install_packages);
    rc_package_slist_ref(status->remove_packages);

    /* Schedule the transaction */
    g_idle_add(run_transaction, status);

    result = xmlrpc_build_value (
        env, "i", rcd_pending_get_id (status->pending));
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

static xmlrpc_value *
packsys_transaction_get_status(xmlrpc_env   *env,
                               xmlrpc_value *param_array,
                               void         *user_data)
{
    xmlrpc_int32 transaction_id;
    RCDPending *pending;
    xmlrpc_value *result;

    xmlrpc_parse_value(
        env, param_array, "(i)",
        &transaction_id);

    pending = rcd_pending_lookup_by_id (transaction_id);
    if (!pending) {
        xmlrpc_env_set_fault (env, -602, "Couldn't find transaction id");
        return NULL;
    }

    result = xmlrpc_build_value (
        env, "s",
        rcd_pending_status_to_string (rcd_pending_get_status (pending)));

    if (env->fault_occurred)
        return NULL;

    return result;
} /* packman_transaction_get_status */

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
    rcd_rpc_register_method(
        "rcd.packsys.query",
        packsys_query,
        rcd_auth_action_list_from_1 (RCD_AUTH_VIEW),
        world);

    rcd_rpc_register_method(
        "rcd.packsys.query_file",
        packsys_query_file,
        rcd_auth_action_list_from_1 (RCD_AUTH_VIEW),
        world);

    rcd_rpc_register_method(
        "rcd.packsys.transact",
        packsys_transact,
        rcd_auth_action_list_from_1 (RCD_AUTH_NONE),
        world);

    rcd_rpc_register_method(
        "rcd.packsys.transaction_get_status",
        packsys_transaction_get_status,
        rcd_auth_action_list_from_1 (RCD_AUTH_VIEW),
        world);

    rcd_rpc_register_method("rcd.packsys.get_channels",
                            packsys_get_channels,
                            rcd_auth_action_list_from_1 (RCD_AUTH_VIEW),
                            world);

    rcd_rpc_register_method("rcd.packsys.refresh_channel",
                            packsys_refresh_channel,
                            rcd_auth_action_list_from_1 (RCD_AUTH_VIEW),
                            world);

#if 0
    rcd_rpc_register_method(
        "rcd.packsys.resolve_dependencies",
        packman_resolve_dependencies,
        packman);
#endif
} /* rcd_rpc_packsys_register_methods */

