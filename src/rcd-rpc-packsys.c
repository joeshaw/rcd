/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include <unistd.h>

#include <xmlrpc.h>

#include "rcd-query-packages.h"
#include "rcd-rpc.h"
#include "rcd-rpc-packsys.h"
#include "rcd-rpc-util.h"

typedef struct {
    RCPackman *packman;

    RCPackageSList *install_packages;
    RCPackageSList *remove_packages;

    int transaction_id;
    gboolean completed;
} RCDPackmanTransactionStatus;

static int current_transaction_id = 0;
static GHashTable *transaction_log = NULL;

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

#if 0
static void
transact_start_cb(RCPackman *packman,
                  int total_steps,
                  RCDPackmanTransactionStatus *status)
{
    printf("Transaction starting.  %d steps\n", total_steps);
} /* transact_start_cb */

static void
transact_step_cb(RCPackman *packman,
                 int seqno,
                 RCPackmanStep step,
                 char *name,
                 RCDPackmanTransactionStatus *status)
{
    printf("Transaction step.  seqno %d\n", seqno);
} /* transact_step_cb */

static void
transact_progress_cb(RCPackman *packman,
                     int amount,
                     int total,
                     RCDPackmanTransactionStatus *status)
{
    printf("Transaction progress.  %d of %d\n", amount, total);
} /* transact_progress_cb */

static void
transact_done_cb(RCPackman *packman,
                 RCDPackmanTransactionStatus *status)
{
    status->completed = TRUE;

    printf("Transaction done\n");
} /* transact_done_cb */

static gboolean
run_transaction(gpointer data)
{
    RCDPackmanTransactionStatus *status = data;

    g_signal_connect(
        G_OBJECT(status->packman), "transact_start",
        G_CALLBACK(transact_start_cb), status);
    g_signal_connect(
        G_OBJECT(status->packman), "transact_step",
        G_CALLBACK(transact_step_cb), status);
    g_signal_connect(
        G_OBJECT(status->packman), "transact_progress",
        G_CALLBACK(transact_progress_cb), status);
    g_signal_connect(
        G_OBJECT(status->packman), "transact_done",
        G_CALLBACK(transact_done_cb), status);

    rc_packman_transact(
        status->packman, status->install_packages, status->remove_packages);

    g_signal_handlers_disconnect_by_func(
        G_OBJECT(status->packman),
        G_CALLBACK(transact_done_cb), status);
    g_signal_handlers_disconnect_by_func(
        G_OBJECT(status->packman),
        G_CALLBACK(transact_start_cb), status);
    g_signal_handlers_disconnect_by_func(
        G_OBJECT(status->packman),
        G_CALLBACK(transact_step_cb), status);
    g_signal_handlers_disconnect_by_func(
        G_OBJECT(status->packman),
        G_CALLBACK(transact_progress_cb), status);

    if (rc_packman_get_error(status->packman)) {
        printf("packman error: %s\n", rc_packman_get_reason(status->packman));
        status->completed = TRUE;
    }

    return FALSE;
} /* run_transaction */

/**** TEMPORARY ****/
static void
rc_package_slist_ref(RCPackageSList *packages)
{
    RCPackageSList *i;

    for (i = packages; i; i = i->next) {
        RCPackage *p = i->data;

        rc_package_ref(p);
    }
} /* rc_package_slist_ref */

static xmlrpc_value *
packman_transact(xmlrpc_env   *env,
                 xmlrpc_value *param_array,
                 void         *user_data)
{
    RCPackman *packman = (RCPackman *) user_data;
    xmlrpc_value *xmlrpc_install_packages;
    xmlrpc_value *xmlrpc_remove_packages;
    RCPackageSList *install_packages = NULL;
    RCPackageSList *remove_packages = NULL;
    RCDPackmanTransactionStatus *status;
    xmlrpc_value *result;

    xmlrpc_parse_value(
        env, param_array, "(AA)",
        &xmlrpc_install_packages, &xmlrpc_remove_packages);
    XMLRPC_FAIL_IF_FAULT(env);

    install_packages = rcd_xmlrpc_parse_package_stream_array(
        packman, xmlrpc_install_packages, env);
    remove_packages = rcd_xmlrpc_parse_package_stream_array(
        packman, xmlrpc_remove_packages, env);

    /* Track our transaction */
    status = g_new0(RCDPackmanTransactionStatus, 1);
    status->packman = packman;
    status->install_packages = install_packages;
    status->remove_packages = remove_packages;
    status->transaction_id = current_transaction_id++;
    status->completed = FALSE;

    rc_package_slist_ref(status->install_packages);
    rc_package_slist_ref(status->remove_packages);

    g_hash_table_insert(
        transaction_log,
        g_strdup_printf("%d", status->transaction_id),
        status);

    /* Schedule the transaction */
    g_idle_add(run_transaction, status);

    result = xmlrpc_build_value(env, "i", status->transaction_id);
    XMLRPC_FAIL_IF_FAULT(env);

cleanup:
    if (install_packages) {
        /* FIXME: This frees the list, it probably shouldn't */
        /* rc_package_slist_unref(install_packages); */
        
        g_slist_foreach(install_packages, (GFunc) rc_package_unref, NULL);
    }

    if (remove_packages) {
        /* FIXME: This frees the list, it probably shouldn't */
        /* rc_package_slist_unref(remove_packages); */

        g_slist_foreach(remove_packages, (GFunc) rc_package_unref, NULL);
    }

    if (env->fault_occurred)
        return NULL;

    return result;
} /* packman_transact */

static xmlrpc_value *
packman_transaction_get_status(xmlrpc_env   *env,
                               xmlrpc_value *param_array,
                               void         *user_data)
{
    xmlrpc_int32 transaction_id;
    char *tid;
    RCDPackmanTransactionStatus *status;
    xmlrpc_value *result;

    xmlrpc_parse_value(
        env, param_array, "(i)",
        &transaction_id);
    
    tid = g_strdup_printf("%d", transaction_id);
    status = g_hash_table_lookup(transaction_log, tid);
    g_free(tid);

    if (!status) {
        xmlrpc_env_set_fault(env, -602, "Couldn't find transaction id");
        return NULL;
    }

    result = xmlrpc_build_value(env, "b", status->completed);

    if (env->fault_occurred)
        return NULL;

    return result;
} /* packman_transact_get_status */

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

#if 0
    rc_package_slist_unref(install_packages);
    rc_package_slist_unref(remove_packages);
#endif
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
    transaction_log = g_hash_table_new(g_str_hash, g_str_equal);

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

    rcd_rpc_register_method("rcd.packsys.get_channels",
                            packsys_get_channels,
                            rcd_auth_action_list_from_1 (RCD_AUTH_VIEW),
                            world);

#if 0
    rcd_rpc_register_method(
        "rcd.packsys.transact",
        packman_transact,
        packman);
    rcd_rpc_register_method(
        "rcd.packsys.transaction_get_status",
        packman_transaction_get_status,
        packman);
    rcd_rpc_register_method(
        "rcd.packsys.resolve_dependencies",
        packman_resolve_dependencies,
        packman);
#endif
} /* rcd_rpc_packsys_register_methods */

