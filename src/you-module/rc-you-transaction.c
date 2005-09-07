/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rc-you-transaction.c
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


#include "rc-you-transaction.h"

#include <unistd.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>

#include <rcd-log.h>
#include <rcd-marshal.h>
#include <rcd-prefs.h>
#include <rcd-rpc-util.h>
#include <rcd-shutdown.h>
#include <rcd-transfer.h>
#include <rcd-transfer-http.h>
#include <rcd-transfer-pool.h>
#include <rcd-world-remote.h>
#include <rcd-xmlrpc.h>

#include "wrapper.h"
#include "you-util.h"
#include "rc-world-you.h"

static GObjectClass *parent_class;

enum {
    TRANSACTION_STARTED,
    TRANSACTION_FINISHED,
    LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };
static GHashTable *abortable_transactions = NULL;

static gboolean check_install_space (RCYouTransaction *transaction, 
                                     GError **err);

static void rc_you_transaction_send_log (RCYouTransaction *transaction,
                                         gboolean          successful,
                                         const char       *message);

#define RC_YOU_TRANSACTION_ERROR_DOMAIN rc_you_transaction_error_quark()

enum {
    RC_YOU_TRANSACTION_ERROR_DOWNLOAD,
    RC_YOU_TRANSACTION_ERROR_TRANSACTION,
    RC_YOU_TRANSACTION_ERROR_DISKSPACE
};

static GQuark
rc_you_transaction_error_quark (void)
{
    static GQuark quark = 0;

    if (quark == 0)
        quark = g_quark_from_static_string ("rc-you-transaction-error-quark");

    return quark;
}

static void
rc_you_transaction_finalize (GObject *obj)
{
    RCYouTransaction *transaction = (RCYouTransaction *) obj;

    g_free (transaction->name);
    g_free (transaction->id);

    rc_you_patch_slist_unref (transaction->patches);
    g_slist_free (transaction->patches);

    rc_you_file_slist_unref (transaction->files_to_download);
    g_slist_free (transaction->files_to_download);

    g_object_unref (transaction->download_pending);
    g_object_unref (transaction->transaction_pending);
    g_object_unref (transaction->transaction_step_pending);

    g_free (transaction->client_id);
    g_free (transaction->client_version);
    g_free (transaction->client_host);
    rcd_identity_free (transaction->client_identity);
}

static void
rc_you_transaction_started_handler (RCYouTransaction *transaction)
{
    /*
     * Ref ourselves so it's safe for users to call g_object_unref()
     * after beginning the transaction.
     */
    g_object_ref (transaction);

    /*
     * We don't want to allow the daemon to be shut down whilc we're in
     * the middle of a transaction.
     */
    rcd_shutdown_block ();
}

static void
rc_you_transaction_finished_handler (RCYouTransaction *transaction)
{
    /*
     * If caching is turned off, we don't want to keep around the
     * files on disk.
     */
    if (!rcd_prefs_get_cache_enabled () &&
        transaction->flags != RCD_TRANSACTION_FLAGS_DOWNLOAD_ONLY)
    {
        RCYouFileSList *iter;

        for (iter = transaction->files_to_download;
             iter; iter = iter->next) {
            RCYouFile *file = iter->data;

            unlink (file->local_path);
            g_free (file->local_path);
            file->local_path = NULL;
        }
    }

    /* Allow shutdowns again */
    rcd_shutdown_allow ();

    /* Lift the transaction lock */
    if (transaction->locked)
        rcd_transaction_unlock ();

    /* Unref ourselves to match the one in the started handler */
    g_object_unref (transaction);
}

static void
rc_you_transaction_class_init (RCYouTransactionClass *klass)
{
    GObjectClass *obj_class = (GObjectClass *) klass;

    parent_class = g_type_class_peek_parent (klass);

    obj_class->finalize = rc_you_transaction_finalize;

    klass->transaction_started = rc_you_transaction_started_handler;
    klass->transaction_finished = rc_you_transaction_finished_handler;

    signals[TRANSACTION_STARTED] =
        g_signal_new ("transaction_started",
                      G_TYPE_FROM_CLASS (klass),
                      G_SIGNAL_RUN_LAST,
                      G_STRUCT_OFFSET (RCYouTransactionClass,
                                       transaction_started),
                      NULL, NULL,
                      rcd_marshal_VOID__VOID,
                      G_TYPE_NONE, 0);

    signals[TRANSACTION_FINISHED] =
        g_signal_new ("transaction_finished",
                      G_TYPE_FROM_CLASS (klass),
                      G_SIGNAL_RUN_LAST,
                      G_STRUCT_OFFSET (RCYouTransactionClass,
                                       transaction_finished),
                      NULL, NULL,
                      rcd_marshal_VOID__VOID,
                      G_TYPE_NONE, 0);
}

static void
rc_you_transaction_init (RCYouTransaction *transaction)
{
    transaction->id = NULL;

    transaction->pool = rcd_transfer_pool_new (TRUE, "Patch download");

    transaction->download_pending =
        g_object_ref (rcd_transfer_pool_get_pending (transaction->pool));

    transaction->transaction_pending =
        rc_pending_new ("Patch transaction");

    transaction->transaction_step_pending =
        rc_pending_new ("Patch transaction step");
}

GType
rc_you_transaction_get_type (void)
{
    static GType type = 0;

    if (!type) {
        static GTypeInfo type_info = {
            sizeof (RCYouTransactionClass),
            NULL, NULL,
            (GClassInitFunc) rc_you_transaction_class_init,
            NULL, NULL,
            sizeof (RCYouTransaction),
            0,
            (GInstanceInitFunc) rc_you_transaction_init
        };

        type = g_type_register_static (G_TYPE_OBJECT,
                                       "RCYouTransaction",
                                       &type_info,
                                       0);
    }

    return type;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

void
rc_you_transaction_emit_transaction_started (RCYouTransaction *transaction)
{
    g_return_if_fail (RC_IS_YOU_TRANSACTION (transaction));

    g_signal_emit (transaction, signals[TRANSACTION_STARTED], 0);
}

void
rc_you_transaction_emit_transaction_finished (RCYouTransaction *transaction)
{
    g_return_if_fail (RC_IS_YOU_TRANSACTION (transaction));

    g_signal_emit (transaction, signals[TRANSACTION_FINISHED], 0);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

RCYouTransaction *
rc_you_transaction_new (void)
{
    RCYouTransaction *transaction;

    transaction = g_object_new (RC_TYPE_YOU_TRANSACTION, NULL);

    return transaction;
}

void
rc_you_transaction_set_name (RCYouTransaction *transaction, const char *name)
{
    g_return_if_fail (RC_IS_YOU_TRANSACTION (transaction));

    transaction->name = g_strdup (name);
}

void
rc_you_transaction_set_patches (RCYouTransaction *transaction,
                                RCYouPatchSList  *patches)
{
    RCYouPatchSList *iter;

    g_return_if_fail (RC_IS_YOU_TRANSACTION (transaction));

    /* Don't trust "them" */

    for (iter = patches; iter; iter = iter->next) {
        RCYouPatch *patch = iter->data;

        if (rc_channel_is_wildcard (patch->channel))
            rc_debug (RC_DEBUG_LEVEL_WARNING,
                      "Could not find channel for patch '%s', ignoring",
                      rc_package_spec_get_name (RC_PACKAGE_SPEC (patch)));
        else
        {
            if (patch->installed)
                rc_debug (RC_DEBUG_LEVEL_WARNING,
                          "Reinstalling already installed patch '%s'",
                          rc_package_spec_get_name (RC_PACKAGE_SPEC (patch)));

            /* ok, accept */
            transaction->patches = g_slist_prepend (transaction->patches,
                                                    rc_you_patch_ref (patch));
        }
    }
}

void
rc_you_transaction_set_flags (RCYouTransaction *transaction,
                              RCDTransactionFlags flags)
{
    g_return_if_fail (RC_IS_YOU_TRANSACTION (transaction));

    transaction->flags = flags;
}

void
rc_you_transaction_set_client_info (RCYouTransaction *transaction,
                                    const char     *client_id,
                                    const char     *client_version,
                                    const char     *client_host,
                                    RCDIdentity    *client_identity)
{
    g_return_if_fail (RC_IS_YOU_TRANSACTION (transaction));

    transaction->client_id = g_strdup (client_id);
    transaction->client_version = g_strdup (client_version);
    transaction->client_host = g_strdup (client_host);
    transaction->client_identity = rcd_identity_copy (client_identity);
}

void
rc_you_transaction_set_id (RCYouTransaction *transaction, const char *id)
{
    g_return_if_fail (RC_IS_YOU_TRANSACTION (transaction));

    transaction->id = g_strdup (id);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

RCPending *
rc_you_transaction_get_download_pending (RCYouTransaction *transaction)
{
    g_return_val_if_fail (RC_IS_YOU_TRANSACTION (transaction), NULL);

    if (transaction->files_to_download == NULL)
        return NULL;

    return transaction->download_pending;
}

RCPending *
rc_you_transaction_get_transaction_pending (RCYouTransaction *transaction)
{
    g_return_val_if_fail (RC_IS_YOU_TRANSACTION (transaction), NULL);

    /* There isn't a transaction component if we're only downloading */
    if (transaction->flags & RCD_TRANSACTION_FLAGS_DOWNLOAD_ONLY)
        return NULL;

    return transaction->transaction_pending;
}

RCPending *
rc_you_transaction_get_step_pending (RCYouTransaction *transaction)
{
    g_return_val_if_fail (RC_IS_YOU_TRANSACTION (transaction), NULL);

    /* There isn't a step component if we're only downloading */
    if (transaction->flags & RCD_TRANSACTION_FLAGS_DOWNLOAD_ONLY)
        return NULL;

    return transaction->transaction_step_pending;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static void
update_log (RCYouTransaction *transaction)
{
    RCYouPatchSList *iter;

    for (iter = transaction->patches; iter; iter = iter->next) {
        RCYouPatch *patch = iter->data;
        RCDLogEntry *log_entry;

        log_entry = rcd_log_entry_new (transaction->client_host,
                                       transaction->client_identity->username);

        /* This is a bit evil, but since it cares about RCPackageSpec ... */
        rcd_log_entry_set_install (log_entry, (RCPackage *) patch);

        rcd_log (log_entry);
        rcd_log_entry_free (log_entry);
    }
} /* update_log */

static void
rc_you_transaction_finished (RCYouTransaction *transaction, const char *msg)
{
    if (transaction->flags != RCD_TRANSACTION_FLAGS_DRY_RUN)
        update_log (transaction);

    rc_you_transaction_send_log (transaction, TRUE, msg);

    rc_you_transaction_emit_transaction_finished (transaction);
}

static void
rc_you_transaction_failed (RCYouTransaction *transaction,
                           RCPending        *pending_to_fail,
                           const char       *msg)
{
    RCPendingStatus status = rc_pending_get_status (pending_to_fail);

    rc_debug (RC_DEBUG_LEVEL_ERROR,
              "Patch transaction failed: %s", msg);

    if (status == RC_PENDING_STATUS_PRE_BEGIN ||
        rc_pending_is_active (pending_to_fail))
    {
        /* We need to be running the pending to fail it */
        if (status == RC_PENDING_STATUS_PRE_BEGIN)
            rc_pending_begin (pending_to_fail);

        rc_pending_fail (pending_to_fail, 0, msg);
    }

    rc_you_transaction_send_log (transaction, FALSE, msg);

    rc_you_transaction_emit_transaction_finished (transaction);
}

static void
refresh_installed_patches (void)
{
    RCWorldService *world;

    world = rc_world_multi_lookup_service_by_id
        (RC_WORLD_MULTI (rc_get_world ()), "@system");

    g_assert (world != NULL);

    rc_world_add_patches (RC_WORLD (world), NULL);
}

/* Ahem */
static void
rc_you_transaction_transaction (RCYouTransaction *transaction)
{
    GError *error = NULL;

    rc_pending_begin (transaction->transaction_pending);
    rc_pending_begin (transaction->transaction_step_pending);

    create_you_directory_structure (transaction->patches, &error);
    if (error)
        goto cleanup;

    if (transaction->flags != RCD_TRANSACTION_FLAGS_DOWNLOAD_ONLY)
        rc_you_wrapper_install_patches (transaction->patches,
                                        transaction->transaction_pending,
                                        transaction->transaction_step_pending,
                                        &error);
    if (error)
        goto cleanup;

    refresh_installed_patches ();

    rc_pending_finished (transaction->transaction_step_pending, 0);
    rc_pending_finished (transaction->transaction_pending, 0);
    rc_you_transaction_finished (transaction, NULL);

 cleanup:
    clean_you_directory_structure ();

    if (error) {
        rc_you_transaction_failed (transaction,
                                   transaction->transaction_pending,
                                   error->message);
        g_error_free (error);
    }
}

static void
rc_you_transaction_verification (RCYouTransaction *transaction)
{
    GError *err = NULL;

    if (rcd_transaction_is_locked ())
        rc_you_transaction_failed (transaction, transaction->transaction_pending,
                                   "Another transaction is already in progress");
    else {
        if (!check_install_space (transaction, &err))
            goto ERROR;

        rcd_transaction_lock ();
        transaction->locked = TRUE;
        rc_you_transaction_transaction (transaction);
    }

 ERROR:
    if (err) {
        rc_you_transaction_failed (transaction,
                                   transaction->transaction_pending,
                                   err->message);
        g_error_free (err);
    }
}

static gchar *
rc_channel_get_patch_path (RCDistro *distro, RCChannel *channel)
{
    gchar *path;
    gchar *sufix;

    sufix = rc_maybe_merge_paths ("getPatch/", rc_distro_get_target (distro));
    path = rc_maybe_merge_paths (rc_channel_get_path (channel), sufix);
    g_free (sufix);

    return path;
}

static gboolean
get_files_to_download (RCYouTransaction *transaction, GError **err)
{
    RCYouPatchSList *iter;
    RCYouPackageSList *pkg_iter;

    transaction->files_to_download = NULL;
    transaction->total_download_size = 0;
    transaction->total_install_size = 0;

    for (iter = transaction->patches; iter; iter = iter->next) {
        RCYouPatch *patch = iter->data;
        RCWorldService *service;
        gchar *channel_path;
        gchar *patch_prefix;
        gchar *pkg_prefix;

        service = RC_WORLD_SERVICE (rc_channel_get_world (patch->channel));

        channel_path = rc_channel_get_patch_path (RCD_WORLD_REMOTE (service)->distro, patch->channel);
        patch_prefix = rc_maybe_merge_paths (service->url, channel_path);
        g_free (channel_path);

        rc_you_file_set_url (patch->file,
                             rc_maybe_merge_paths (patch_prefix, patch->file->filename));

        transaction->files_to_download =
            g_slist_prepend (transaction->files_to_download,
                             rc_you_file_ref (patch->file));

        if (patch->pre_script) {
            rc_you_file_set_url (patch->pre_script,
                                 rc_maybe_merge_paths (patch_prefix,
                                                       patch->pre_script->filename));
            transaction->files_to_download =
            g_slist_prepend (transaction->files_to_download,
                             rc_you_file_ref (patch->pre_script));
        }

        if (patch->post_script) {
            rc_you_file_set_url (patch->post_script,
                                 rc_maybe_merge_paths (patch_prefix,
                                                       patch->post_script->filename));
            transaction->files_to_download =
                g_slist_prepend (transaction->files_to_download,
                                 rc_you_file_ref (patch->post_script));
        }

        pkg_prefix = rc_maybe_merge_paths (service->url,
                                           rc_channel_get_file_path (patch->channel));

        for (pkg_iter = patch->packages; pkg_iter; pkg_iter = pkg_iter->next) {
            RCYouPackage *package = pkg_iter->data;

            /* Download patch rpm only if "real" rpm is not provided */

            if (package->base_package) {
                rc_you_file_set_url (package->base_package,
                                     rc_maybe_merge_paths (pkg_prefix,
                                                           package->base_package->filename));

                transaction->files_to_download = 
                    g_slist_prepend (transaction->files_to_download,
                                     rc_you_file_ref (package->base_package));

                transaction->total_download_size += package->base_package->size;
                transaction->total_install_size += package->patch_rpm_size;
            } else if (package->patch_rpm) {
                rc_you_file_set_url (package->patch_rpm,
                                     rc_maybe_merge_paths (patch_prefix,
                                                           package->patch_rpm->filename));

                transaction->files_to_download = 
                    g_slist_prepend (transaction->files_to_download,
                                     rc_you_file_ref (package->patch_rpm));
            }
        }

        g_free (patch_prefix);
        g_free (pkg_prefix);
    }

    return TRUE;
}

static const char *
format_size (gsize size)
{
    static char *output = NULL;

    g_free (output);

    if (size > 1024 * 1024 * 1024) {
        output = g_strdup_printf (
            "%.2fg", (float) size / (float) (1024 * 1024 * 1024));
    }
    else if (size > 1024 * 1024) {
        output = g_strdup_printf (
            "%.2fM", (float) size / (float) (1024 * 1024));
    }
    else if (size > 1024)
        output = g_strdup_printf ("%.2fk", (float) size / 1024.0);
    else
        output = g_strdup_printf ("%ldb", (long) size);

    return output;
} /* format_size */

static gboolean
check_install_space (RCYouTransaction *transaction, GError **err)
{
    gsize block_size;
    gsize avail_blocks;
    struct statvfs vfs_info;

    if (!transaction->total_install_size)
        return TRUE;

    if (statvfs("/", &vfs_info)) {
        g_set_error (err, RC_YOU_TRANSACTION_ERROR_DOMAIN,
                     RC_YOU_TRANSACTION_ERROR_DISKSPACE,
                     "Unable to get disk space info for /");
        return FALSE;
    }

    block_size = vfs_info.f_frsize;
    avail_blocks = vfs_info.f_bavail;

    if (transaction->total_install_size / block_size + 1 > avail_blocks) {
        g_set_error (err, RC_YOU_TRANSACTION_ERROR_DOMAIN,
                     RC_YOU_TRANSACTION_ERROR_DISKSPACE,
                     "Insufficient disk space: %s needed in /",
                     format_size (transaction->total_install_size));

        return FALSE;
    }

    return TRUE;
} /*  check_install_space */

static gboolean
check_download_space (RCYouTransaction *transaction, GError **err)
{
    gsize block_size;
    gsize avail_blocks;
    struct statvfs vfs_info;
    const char *cache_dir = rcd_prefs_get_cache_dir ();

    /* nothing to download... */
    if (!transaction->total_download_size)
        return TRUE;

    if (!g_path_is_absolute (cache_dir)) {
        g_set_error (err, RC_YOU_TRANSACTION_ERROR_DOMAIN,
                     RC_YOU_TRANSACTION_ERROR_DOWNLOAD,
                     "Cache directory is invalid: '%s'",
                     cache_dir);
        return FALSE;
    }

    if (!g_file_test (cache_dir, G_FILE_TEST_EXISTS))
        rc_mkdir (cache_dir, 0755);

    if (statvfs (cache_dir, &vfs_info)) {
        g_set_error (err, RC_YOU_TRANSACTION_ERROR_DOMAIN,
                     RC_YOU_TRANSACTION_ERROR_DOWNLOAD,
                     "Unable to get disk space info for '%s'",
                     cache_dir);
        return FALSE;
    }

    block_size = vfs_info.f_frsize;
    avail_blocks = vfs_info.f_bavail;

    if (transaction->total_download_size / block_size + 1 > avail_blocks) {
        g_set_error (err, RC_YOU_TRANSACTION_ERROR_DOMAIN,
                     RC_YOU_TRANSACTION_ERROR_DOWNLOAD,
                     "Insufficient disk space: %s needed in %s",
                     format_size (transaction->total_download_size),
                     cache_dir);

        return FALSE;
    }
    else
        return TRUE;
} /* check_download_space */

static void
transfer_done_cb (RCDTransferPool  *pool,
                  RCDTransferError  err,
                  RCYouTransaction *transaction)
{
    g_hash_table_remove (abortable_transactions,
                         transaction->download_pending);

    if (!err) {
        if (transaction->flags == RCD_TRANSACTION_FLAGS_DOWNLOAD_ONLY)
            rc_you_transaction_finished (transaction, NULL);
        else
            rc_you_transaction_verification (transaction);
    }
    else {
        rc_you_transaction_failed (transaction,
                                   transaction->download_pending,
                                   rcd_transfer_error_to_string (err));
    }
}

static void
data_completed_cb (RCDTransfer *t, gpointer user_data)
{
    RCYouFile *file = user_data;

    rc_you_file_set_local_path (file,
                                rcd_transfer_get_local_filename (t));
}

static void
fetch_data (RCDTransferPool *pool, GSList *files)
{
    GSList *iter;

    g_return_if_fail (pool != NULL);

    for (iter = files; iter; iter = iter->next) {
        RCDCacheEntry *entry;
        RCDTransfer *t;
        RCYouFile *file = iter->data;

        entry = rcd_cache_lookup (rcd_cache_get_normal_cache (),
                                  "patch_data", file->filename, TRUE);
        t = rcd_transfer_new (file->url,
                              RCD_TRANSFER_FLAGS_FORCE_CACHE |
                              RCD_TRANSFER_FLAGS_RESUME_PARTIAL,
                              entry);
        rcd_cache_entry_unref (entry);

        g_signal_connect (t, "file_done",
                          G_CALLBACK (data_completed_cb), file);
        rcd_transfer_pool_add_transfer (pool, t);
        g_object_unref (t);
    }
}

static void
rc_you_transaction_download (RCYouTransaction *transaction)
{
    GError *err = NULL;

    if (transaction->files_to_download) {
        if (!check_download_space (transaction, &err))
            goto ERROR;

        if (!abortable_transactions) {
            abortable_transactions = g_hash_table_new_full (NULL, NULL,
                                                            g_object_unref,
                                                            g_object_unref);
        }

        g_hash_table_insert (abortable_transactions,
                             g_object_ref (transaction->download_pending),
                             g_object_ref (transaction));

        /* Kick off the download */
        fetch_data (transaction->pool,
                    transaction->files_to_download);

        rcd_transfer_pool_set_expected_size (transaction->pool,
                                             transaction->total_download_size);
        g_signal_connect (transaction->pool, "transfer_done",
                          G_CALLBACK (transfer_done_cb), transaction);
        rcd_transfer_pool_begin (transaction->pool);
    }
    else {
        if (transaction->flags == RCD_TRANSACTION_FLAGS_DOWNLOAD_ONLY)
            rc_you_transaction_finished (transaction, NULL);
        else
            rc_you_transaction_verification (transaction);
    }

    return;

ERROR:

    rc_you_transaction_failed (transaction,
                               err->code == RC_YOU_TRANSACTION_ERROR_DOWNLOAD ?
                               transaction->download_pending :
                               transaction->transaction_pending,
                               err->message);
    g_error_free (err);
}

static gboolean
begin_transaction_cb (gpointer user_data)
{
    RCYouTransaction *transaction = user_data;

    rc_you_transaction_download (transaction);

    return FALSE;
}

void
rc_you_transaction_begin (RCYouTransaction *transaction)
{
    GError *err = NULL;

    g_return_if_fail (RC_IS_YOU_TRANSACTION (transaction));

    rc_you_transaction_emit_transaction_started (transaction);

    if (!transaction->patches) {
        rc_you_transaction_finished (transaction, "No action required.");
        return;
    }

    /*
     * This function fills out the files_to_download and
     * total_download_size fields of the RCYouTransaction.
     */
    if (!get_files_to_download (transaction, &err)) {
        rc_you_transaction_failed (transaction,
                                   transaction->transaction_pending,
                                   err->message);
        g_error_free (err);
        return;
    }

    g_idle_add (begin_transaction_cb, transaction);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static RCYouTransaction *
get_transaction_from_id (int download_id)
{
    RCPending *pending;

    if (!abortable_transactions)
        return NULL;

    pending = rc_pending_lookup_by_id (download_id);

    if (!pending)
        return NULL;

    return g_hash_table_lookup (abortable_transactions, pending);
} /* get_transaction_from_id */

gboolean
rc_you_transaction_is_valid (int download_id)
{
    return get_transaction_from_id (download_id) != NULL;
}

static gboolean
check_install_auth (RCYouTransaction *transaction, RCDIdentity *identity)
{
    RCDPrivileges req_priv;

    if (!transaction->patches)
        return TRUE;

    req_priv = rcd_privileges_from_string ("install");
    return rcd_identity_approve_action (identity, req_priv);
} /* check_install_auth */

int
rc_you_transaction_abort (int download_id, RCDIdentity *identity)
{
    RCYouTransaction *transaction;

    transaction = get_transaction_from_id (download_id);

    if (!transaction)
        return 0;

    /* Check our permissions to abort this download */
    if (!check_install_auth (transaction, identity))
        return -1;

    rcd_transfer_pool_abort (transaction->pool);

    return 1;
} /* rc_you_transaction_abort */

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static xmlrpc_value *
you_patch_to_xmlrpc (xmlrpc_env *env, RCYouPatch *patch)
{
    RCPackageSpec *spec = RC_PACKAGE_SPEC (patch);
    xmlrpc_value *xpatch = NULL;

    xpatch = xmlrpc_struct_new (env);
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_SET_STRING
        (env, xpatch, "name", rc_package_spec_get_name (spec));
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_SET_STRING (env, xpatch, "version",
                                  rc_package_spec_version_to_str_static (spec));
    XMLRPC_FAIL_IF_FAULT (env);

 cleanup:
    if (env->fault_occurred && xpatch != NULL) {
        xmlrpc_DECREF (xpatch);
        xpatch = NULL;
    }

    return xpatch;
}

static xmlrpc_value *
you_transaction_xml (xmlrpc_env       *env,
                     RCYouTransaction *transaction,
                     gboolean          successful,
                     const char       *message)
{
    xmlrpc_value *xtrans;
    xmlrpc_value *xmanifests;
    RCYouPatchSList *iter;

    /* Common part for all logs */
    xtrans = xmlrpc_struct_new (env);
    XMLRPC_FAIL_IF_FAULT (env);

    if (transaction->id) {
        RCD_XMLRPC_STRUCT_SET_STRING (env, xtrans, "trid", transaction->id);
        XMLRPC_FAIL_IF_FAULT (env);
    }

    RCD_XMLRPC_STRUCT_SET_INT (env, xtrans, "endtime", time (NULL));
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_SET_STRING (env, xtrans, "client",
                                  transaction->client_id);
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_SET_STRING (env, xtrans, "version",
                                  transaction->client_version);
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_SET_INT (env, xtrans, "status",
                               successful ? 1 : 0);
    XMLRPC_FAIL_IF_FAULT (env);

    if (message) {
        RCD_XMLRPC_STRUCT_SET_STRING (env, xtrans, "message", message);
        XMLRPC_FAIL_IF_FAULT (env);
    }

    /* Transaction part */

    RCD_XMLRPC_STRUCT_SET_STRING (env, xtrans, "log_type", "patch");
    XMLRPC_FAIL_IF_FAULT (env);

    if (transaction->flags & RCD_TRANSACTION_FLAGS_DRY_RUN) {
        RCD_XMLRPC_STRUCT_SET_INT (env, xtrans, "dry_run", 1);
        XMLRPC_FAIL_IF_FAULT (env);
    }

    if (transaction->flags & RCD_TRANSACTION_FLAGS_DOWNLOAD_ONLY) {
        RCD_XMLRPC_STRUCT_SET_INT (env, xtrans, "preposition", 1);
        XMLRPC_FAIL_IF_FAULT (env);
    }

    xmanifests = xmlrpc_build_value (env, "()");
    XMLRPC_FAIL_IF_FAULT (env);
    xmlrpc_struct_set_value (env, xtrans, "patches", xmanifests);
    XMLRPC_FAIL_IF_FAULT (env);
    xmlrpc_DECREF (xmanifests);

    for (iter = transaction->patches; iter; iter = iter->next) {
        RCYouPatch *p = iter->data;
        xmlrpc_value *xpatch;

        xpatch = you_patch_to_xmlrpc (env, p);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_array_append_item (env, xmanifests, xpatch);
        XMLRPC_FAIL_IF_FAULT (env);
        xmlrpc_DECREF (xpatch);
    }

cleanup:

    return xtrans;
} /* transaction_xml */

static void
log_sent_cb (char *server_url,
             char *method_name,
             xmlrpc_value *param_array,
             void *user_data,
             xmlrpc_env *fault,
             xmlrpc_value *result)
{
    if (fault->fault_occurred) {
        rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Unable to send data to '%s': %s",
                  server_url, fault->fault_string);
    }
}

static void
rc_you_transaction_send_log (RCYouTransaction *transaction,
                             gboolean          successful,
                             const char       *message)
{
    xmlrpc_env env;
    xmlrpc_value *params;
    xmlrpc_value *transaction_log = NULL;

    xmlrpc_env_init (&env);

    transaction_log = you_transaction_xml (&env, transaction,
                                           successful, message);
    XMLRPC_FAIL_IF_FAULT (&env);

    params = xmlrpc_build_value (&env, "(V)", transaction_log);
    XMLRPC_FAIL_IF_FAULT (&env);

    rcd_xmlrpc_client_foreach_host (TRUE, "rcserver.transaction.log",
                                    log_sent_cb, NULL,
                                    params);
    xmlrpc_DECREF (params);

cleanup:
    xmlrpc_env_clean (&env);

    if (transaction_log)
        xmlrpc_DECREF (transaction_log);
} /* rcd_transaction_send_log */
