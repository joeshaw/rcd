/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-transaction.c
 *
 * Copyright (C) 2000-2002 Ximian, Inc.
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
#include "rcd-transaction.h"

#include <unistd.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>

#include "rcd-fetch.h"
#include "rcd-log.h"
#include "rcd-marshal.h"
#include "rcd-pending.h"
#include "rcd-prefs.h"
#include "rcd-shutdown.h"
#include "rcd-transfer.h"
#include "rcd-transfer-http.h"
#include "rcd-transfer-pool.h"

static GObjectClass *parent_class;

enum {
    TRANSACTION_STARTED,
    TRANSACTION_FINISHED,
    LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static gboolean transaction_lock = FALSE;
static GHashTable *abortable_transactions = NULL;


#define RCD_TRANSACTION_ERROR_DOMAIN rcd_transaction_error_quark()

enum {
    RCD_TRANSACTION_ERROR_DOWNLOAD,
    RCD_TRANSACTION_ERROR_TRANSACTION
};

static GQuark
rcd_transaction_error_quark (void)
{
    static GQuark quark = 0;

    if (quark == 0)
        quark = g_quark_from_static_string ("rcd-transaction-error-quark");

    return quark;
}

static void
rcd_transaction_finalize (GObject *obj)
{
    RCDTransaction *transaction = (RCDTransaction *) obj;

    g_free (transaction->name);

    rc_package_slist_unref (transaction->install_packages);
    g_slist_free (transaction->install_packages);

    rc_package_slist_unref (transaction->remove_packages);
    g_slist_free (transaction->remove_packages);

    rc_package_slist_unref (transaction->packages_to_download);
    g_slist_free (transaction->packages_to_download);

    g_object_unref (transaction->download_pending);
    g_object_unref (transaction->transaction_pending);
    g_object_unref (transaction->transaction_step_pending);
    
    g_free (transaction->client_id);
    g_free (transaction->client_version);
    g_free (transaction->client_host);
    rcd_identity_free (transaction->client_identity);
}

static void
rcd_transaction_started_handler (RCDTransaction *transaction)
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
rcd_transaction_finished_handler (RCDTransaction *transaction)
{
    /* Reload the system packages */
    rc_world_get_system_packages (transaction->world);

    /*
     * If caching is turned off, we don't want to keep around the package
     * files on disk.
     */
    if (!rcd_prefs_get_cache_enabled () &&
        transaction->flags != RCD_TRANSACTION_FLAGS_DOWNLOAD_ONLY)
    {
        RCPackageSList *iter;

        for (iter = transaction->packages_to_download;
             iter; iter = iter->next)
        {
            RCPackage *p = iter->data;

            unlink (p->package_filename);
            g_free (p->package_filename);
            p->package_filename = NULL;
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
rcd_transaction_class_init (RCDTransactionClass *klass)
{
    GObjectClass *obj_class = (GObjectClass *) klass;

    parent_class = g_type_class_peek_parent (klass);

    obj_class->finalize = rcd_transaction_finalize;

    klass->transaction_started = rcd_transaction_started_handler;
    klass->transaction_finished = rcd_transaction_finished_handler;

    signals[TRANSACTION_STARTED] =
        g_signal_new ("transaction_started",
                      G_TYPE_FROM_CLASS (klass),
                      G_SIGNAL_RUN_LAST,
                      G_STRUCT_OFFSET (RCDTransactionClass,
                                       transaction_started),
                      NULL, NULL,
                      rcd_marshal_VOID__VOID,
                      G_TYPE_NONE, 0);

    signals[TRANSACTION_FINISHED] =
        g_signal_new ("transaction_finished",
                      G_TYPE_FROM_CLASS (klass),
                      G_SIGNAL_RUN_LAST,
                      G_STRUCT_OFFSET (RCDTransactionClass,
                                       transaction_finished),
                      NULL, NULL,
                      rcd_marshal_VOID__VOID,
                      G_TYPE_NONE, 0);
}

static void
rcd_transaction_init (RCDTransaction *transaction)
{
    transaction->world = rc_get_world ();

    transaction->pool = rcd_transfer_pool_new (TRUE);

    transaction->download_pending =
        g_object_ref (rcd_transfer_pool_get_pending (transaction->pool));
    rcd_pending_set_description (transaction->download_pending,
                                 "Package download");

    transaction->transaction_pending =
        rcd_pending_new ("Package transaction");

    transaction->transaction_step_pending =
        rcd_pending_new ("Package transaction step");
}

GType
rcd_transaction_get_type (void)
{
    static GType type = 0;

    if (!type) {
        static GTypeInfo type_info = {
            sizeof (RCDTransactionClass),
            NULL, NULL,
            (GClassInitFunc) rcd_transaction_class_init,
            NULL, NULL,
            sizeof (RCDTransaction),
            0,
            (GInstanceInitFunc) rcd_transaction_init
        };

        type = g_type_register_static (G_TYPE_OBJECT,
                                       "RCDTransaction",
                                       &type_info,
                                       0);
    }

    return type;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

void
rcd_transaction_emit_transaction_started (RCDTransaction *transaction)
{
    g_return_if_fail (RCD_IS_TRANSACTION (transaction));

    g_signal_emit (transaction, signals[TRANSACTION_STARTED], 0);
}

void
rcd_transaction_emit_transaction_finished (RCDTransaction *transaction)
{
    g_return_if_fail (RCD_IS_TRANSACTION (transaction));

    g_signal_emit (transaction, signals[TRANSACTION_FINISHED], 0);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

RCDTransaction *
rcd_transaction_new (void)
{
    RCDTransaction *transaction;

    transaction = g_object_new (RCD_TYPE_TRANSACTION, NULL);

    return transaction;
}

void
rcd_transaction_set_name (RCDTransaction *transaction, const char *name)
{
    g_return_if_fail (RCD_IS_TRANSACTION (transaction));

    transaction->name = g_strdup (name);
}

void
rcd_transaction_set_install_packages (RCDTransaction *transaction,
                                      RCPackageSList *install_packages)
{
    g_return_if_fail (RCD_IS_TRANSACTION (transaction));

    transaction->install_packages =
        g_slist_copy (rc_package_slist_ref (install_packages));
}

void
rcd_transaction_set_remove_packages (RCDTransaction *transaction,
                                     RCPackageSList *remove_packages)
{
    g_return_if_fail (RCD_IS_TRANSACTION (transaction));

    transaction->remove_packages =
        g_slist_copy (rc_package_slist_ref (remove_packages));
}

void
rcd_transaction_set_flags (RCDTransaction *transaction,
                           RCDTransactionFlags flags)
{
    g_return_if_fail (RCD_IS_TRANSACTION (transaction));

    transaction->flags = flags;
}

void
rcd_transaction_set_client_info (RCDTransaction *transaction,
                                 const char     *client_id,
                                 const char     *client_version,
                                 const char     *client_host,
                                 RCDIdentity    *client_identity)
{
    g_return_if_fail (RCD_IS_TRANSACTION (transaction));

    transaction->client_id = g_strdup (client_id);
    transaction->client_version = g_strdup (client_version);
    transaction->client_host = g_strdup (client_host);
    transaction->client_identity = rcd_identity_copy (client_identity);
}

int
rcd_transaction_get_download_pending_id (RCDTransaction *transaction)
{
    g_return_val_if_fail (RCD_IS_TRANSACTION (transaction), -1);

    if (transaction->packages_to_download == NULL)
        return -1;

    return rcd_pending_get_id (transaction->download_pending);
}

int
rcd_transaction_get_transaction_pending_id (RCDTransaction *transaction)
{
    g_return_val_if_fail (RCD_IS_TRANSACTION (transaction), -1);

    /* There isn't a transaction component if we're only downloading */
    if (transaction->flags & RCD_TRANSACTION_FLAGS_DOWNLOAD_ONLY)
        return -1;

    return rcd_pending_get_id (transaction->transaction_pending);
}

int
rcd_transaction_get_step_pending_id (RCDTransaction *transaction)
{
    g_return_val_if_fail (RCD_IS_TRANSACTION (transaction), -1);

    /* There isn't a step component if we're only downloading */
    if (transaction->flags & RCD_TRANSACTION_FLAGS_DOWNLOAD_ONLY)
        return -1;

    return rcd_pending_get_id (transaction->transaction_step_pending);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static void
update_log (RCDTransaction *transaction)
{
    RCPackageSList *iter;

    for (iter = transaction->install_packages; iter; iter = iter->next) {
        RCPackage *new_p = iter->data;
        RCPackage *old_p;
        RCDLogEntry *log_entry;

        log_entry = rcd_log_entry_new (transaction->client_host,
                                       transaction->client_identity->username);

        old_p = rc_world_get_package (rc_get_world (),
                                      RC_CHANNEL_SYSTEM,
                                      g_quark_to_string (new_p->spec.nameq));

        if (old_p)
            rcd_log_entry_set_upgrade (log_entry, old_p, new_p);
        else
            rcd_log_entry_set_install (log_entry, new_p);

        rcd_log (log_entry);
        rcd_log_entry_free (log_entry);
    }

    for (iter = transaction->remove_packages; iter; iter = iter->next) {
        RCPackage *p = iter->data;
        RCDLogEntry *log_entry;

        log_entry = rcd_log_entry_new (transaction->client_host,
                                       transaction->client_identity->username);
        rcd_log_entry_set_remove (log_entry, p);
        rcd_log (log_entry);
        rcd_log_entry_free (log_entry);
    }
} /* update_log */

static void
rcd_transaction_finished (RCDTransaction *transaction, const char *msg)
{
    if (transaction->flags != RCD_TRANSACTION_FLAGS_DRY_RUN)
        update_log (transaction);

#if 0
    if (rcd_prefs_get_premium ())
        rcd_transaction_send_log (transaction, TRUE, msg);
#endif

    rcd_transaction_emit_transaction_finished (transaction);
}

static void
rcd_transaction_failed (RCDTransaction *transaction,
                        RCDPending     *pending_to_fail,
                        const char     *msg)
{
    RCDPendingStatus status = rcd_pending_get_status (pending_to_fail);

    if (status == RCD_PENDING_STATUS_PRE_BEGIN ||
        rcd_pending_is_active (pending_to_fail))
    {
        /* We need to be running the pending to fail it */
        if (status == RCD_PENDING_STATUS_PRE_BEGIN)
            rcd_pending_begin (pending_to_fail);

        rcd_pending_fail (pending_to_fail, 0, msg);
    }

#if 0
    if (rcd_prefs_get_premium ())
        rcd_transaction_send_log (transaction, FALSE, msg);
#endif

    rcd_transaction_emit_transaction_finished (transaction);
}

static void
transact_start_cb(RCPackman *packman,
                  int total_steps,
                  RCDTransaction *transaction)
{
    rc_debug (RC_DEBUG_LEVEL_MESSAGE,
              "Transaction starting.  %d steps", total_steps);

    rcd_pending_begin (transaction->transaction_pending);
    rcd_pending_begin (transaction->transaction_step_pending);

    transaction->total_transaction_steps = total_steps;
} /* transact_start_cb */

static void
transact_step_cb(RCPackman *packman,
                 int seqno,
                 RCPackmanStep step,
                 char *name,
                 RCDTransaction *transaction)
{
    char *action = NULL;
    char *msg;
    const char *last;

    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Transaction step.  seqno %d", seqno);

    transaction->transaction_size = 0;

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

    /* We don't want to push the same message multiple times */
    last = rcd_pending_get_latest_message (transaction->transaction_pending);
    if (!last || strcmp (msg, last) != 0)
        rcd_pending_add_message (transaction->transaction_pending, msg);

    g_free (msg);

    rcd_pending_update_by_size (transaction->transaction_pending, seqno - 1,
                                transaction->total_transaction_steps);
} /* transact_step_cb */

static void
transact_progress_cb(RCPackman *packman,
                     int amount,
                     int total,
                     RCDTransaction *transaction)
{
    rc_debug (RC_DEBUG_LEVEL_INFO,
              "Transaction progress.  %d of %d", amount, total);

    if (transaction->transaction_size == 0) {
        if (rcd_pending_get_status (transaction->transaction_step_pending) ==
            RCD_PENDING_STATUS_PRE_BEGIN)
            rcd_pending_begin (transaction->transaction_step_pending);
        else
            rcd_pending_update (transaction->transaction_step_pending, 0);
    }

    if (total && amount > transaction->transaction_size) {
        rcd_pending_update_by_size (transaction->transaction_step_pending,
                                    amount, total);
    }
} /* transact_progress_cb */

static void
transact_done_cb(RCPackman *packman,
                 RCDTransaction *transaction)
{
    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Transaction done");

    rcd_pending_finished (transaction->transaction_pending, 0);
    if (rcd_pending_get_status (transaction->transaction_step_pending) !=
        RCD_PENDING_STATUS_PRE_BEGIN)
        rcd_pending_finished (transaction->transaction_step_pending, 0);
} /* transact_done_cb */

/* Ahem */
static void
rcd_transaction_transaction (RCDTransaction *transaction)
{
    RCPackman *packman = rc_world_get_packman (transaction->world);
    int flags = 0;

    g_signal_connect (packman, "transact_start",
                      G_CALLBACK (transact_start_cb), transaction);
    g_signal_connect (packman, "transact_step",
                      G_CALLBACK (transact_step_cb), transaction);
    g_signal_connect (packman, "transact_progress",
                      G_CALLBACK (transact_progress_cb), transaction);
    g_signal_connect (packman, "transact_done",
                      G_CALLBACK (transact_done_cb), transaction);

    if (transaction->flags == RCD_TRANSACTION_FLAGS_DRY_RUN)
        flags |= RC_TRANSACT_FLAG_NO_ACT;

    rc_world_transact (transaction->world,
                       transaction->install_packages,
                       transaction->remove_packages,
                       flags);

    g_signal_handlers_disconnect_by_func (packman,
                                          G_CALLBACK (transact_start_cb),
                                          transaction);
    g_signal_handlers_disconnect_by_func (packman,
                                          G_CALLBACK (transact_step_cb),
                                          transaction);
    g_signal_handlers_disconnect_by_func (packman,
                                          G_CALLBACK (transact_progress_cb),
                                          transaction);
    g_signal_handlers_disconnect_by_func (packman,
                                          G_CALLBACK (transact_done_cb),
                                          transaction);

    if (rc_packman_get_error (packman)) {
        rcd_transaction_failed (transaction,
                                transaction->transaction_pending,
                                rc_packman_get_reason (packman));

        return;
    }

    rcd_transaction_finished (transaction, NULL);
}

static void
rcd_transaction_verification (RCDTransaction *transaction)
{
    RCPackman *packman = rc_world_get_packman (transaction->world);
    GError *err = NULL;
    RCPackageSList *iter;

    if (rcd_transaction_is_locked ()) {
        g_set_error (&err,
                     RCD_TRANSACTION_ERROR_DOMAIN,
                     RCD_TRANSACTION_ERROR_TRANSACTION,
                     "Another transaction is already in progress");
        goto ERROR;
    }

    rcd_transaction_lock ();
    transaction->locked = TRUE;

    for (iter = transaction->install_packages; iter; iter = iter->next) {
        RCPackage *package = iter->data;
        char *msg;
        RCVerificationSList *vers;
        RCVerificationStatus worst_status = RC_VERIFICATION_STATUS_PASS;
        gboolean gpg_attempted = FALSE;
        GSList *v;

        if (rc_package_is_synthetic (package))
            continue;

        /* Flush the main loop queue for maximum responsivity */
        while (g_main_pending ())
            g_main_iteration (TRUE);

        msg = g_strconcat ("verify:", g_quark_to_string (package->spec.nameq),
                           NULL);
        rcd_pending_add_message (transaction->transaction_pending, msg);
        g_free (msg);

        vers = rc_packman_verify (packman, package,
                                  RC_VERIFICATION_TYPE_ALL);

        if (rc_packman_get_error (packman)) {
            g_set_error (&err,
                         RCD_TRANSACTION_ERROR_DOMAIN,
                         RCD_TRANSACTION_ERROR_TRANSACTION,
                         "%s", rc_packman_get_reason (packman));
            goto ERROR;
        }

        for (v = vers; v; v = v->next) {
            RCVerification *ver = v->data;

            if (worst_status > ver->status)
                worst_status = ver->status;

            if (ver->type == RC_VERIFICATION_TYPE_GPG)
                gpg_attempted = TRUE;
        }

        rc_verification_slist_free (vers);

        if (worst_status == RC_VERIFICATION_STATUS_FAIL) {
            rc_debug (RC_DEBUG_LEVEL_MESSAGE,
                      "Verification of '%s' failed",
                      g_quark_to_string (package->spec.nameq));

            g_set_error (&err,
                         RCD_TRANSACTION_ERROR_DOMAIN,
                         RCD_TRANSACTION_ERROR_TRANSACTION,
                         "Verification of '%s' failed",
                         g_quark_to_string (package->spec.nameq));
            goto ERROR;
        }
        else if (worst_status == RC_VERIFICATION_STATUS_UNDEF ||
                 !gpg_attempted)
        {
            char *status_msg;
            gboolean is_trusted;

            if (!gpg_attempted) {
                msg =
                    g_strdup_printf ("Package '%s' is not signed",
                                     g_quark_to_string (package->spec.nameq));
            }
            else {
                msg =
                    g_strdup_printf ("Unable to verify package signature "
                                     "for '%s'",
                                     g_quark_to_string (package->spec.nameq));
            }

            rc_debug (RC_DEBUG_LEVEL_MESSAGE, msg);
        
            is_trusted = rcd_identity_approve_action (
                transaction->client_identity,
                rcd_privileges_from_string ("trusted"));

            if (is_trusted) {
                status_msg = g_strconcat (
                    gpg_attempted ? "verify-undef:" : "verify-nosig:",
                    g_quark_to_string (package->spec.nameq),
                    "; package will be installed because user is trusted",
                    NULL);
            }
            else {
                status_msg = g_strconcat (
                    gpg_attempted ? "verify-undef:" : "verify-nosig:",
                    g_quark_to_string (package->spec.nameq),
                    NULL);
            }

            rcd_pending_add_message (transaction->transaction_pending,
                                     status_msg);
            g_free (status_msg);

            if (!is_trusted && rcd_prefs_get_require_signed_packages ()) {
                g_set_error (&err,
                             RCD_TRANSACTION_ERROR_DOMAIN,
                             RCD_TRANSACTION_ERROR_TRANSACTION,
                             "%s; verified package signatures are required "
                             "for installation",
                             msg);

                g_free (msg);
                goto ERROR;
            }

            g_free (msg);
        }
    }

    rcd_transaction_transaction (transaction);
    return;

ERROR:
    rcd_transaction_failed (transaction, transaction->transaction_pending,
                            err->message);
    g_error_free (err);
}

static gboolean
get_packages_to_download (RCDTransaction *transaction, GError **err)
{
    RCPackageSList *iter;

    transaction->packages_to_download = NULL;
    transaction->total_download_size = 0;

    for (iter = transaction->install_packages; iter; iter = iter->next) {
        RCPackage *package = iter->data;

        /* Skip synthetic packages, since there's nothing to actually
           download */
        if (rc_package_is_synthetic (package))
            continue;

        if (package->package_filename) {
            if (!g_file_test (package->package_filename, G_FILE_TEST_EXISTS)) {
                g_free (package->package_filename);
                package->package_filename = NULL;
            }
            else {
                if (!rcd_transaction_check_package_integrity (
                        package->package_filename))
                {
                    RCDCacheEntry *entry;

                    entry = rcd_cache_lookup (rcd_cache_get_package_cache (),
                                              package->package_filename);

                    if (entry)
                        rcd_cache_entry_invalidate (entry);

                    /*
                     * We can't download another version of this package
                     * because it isn't in a channel, and therefore has
                     * nothing in its hgistory section
                     */
                    if (!rc_package_get_latest_update (package)) {
                        g_set_error (err, RCD_TRANSACTION_ERROR_DOMAIN,
                                     RCD_TRANSACTION_ERROR_TRANSACTION,
                                     "%s is not a valid package",
                                     package->package_filename);

                        g_free (package->package_filename);
                        package->package_filename = NULL;

                        return FALSE;
                    }

                    g_free (package->package_filename);
                    package->package_filename = NULL;
                }
            }
        }

        /*
         * The package file isn't already on the system, so we have to
         * download it.
         */
        if (!package->package_filename) {
            RCPackageUpdate *update;

            update = rc_package_get_latest_update (package);

            /*
             * Hmm, we got passed a request to install a package that's
             * already installed and for which we don't have an update.
             * This transaction is going to fail.
             */

            if (!update) {
                g_set_error (err, RCD_TRANSACTION_ERROR_DOMAIN,
                             RCD_TRANSACTION_ERROR_TRANSACTION,
                             "Package %s is already installed",
                             rc_package_spec_to_str_static (
                                 RC_PACKAGE_SPEC (package)));

                return FALSE;
            }
            else {
                transaction->packages_to_download =
                    g_slist_prepend (transaction->packages_to_download,
                                     rc_package_ref (package));

                transaction->total_download_size += update->package_size;
            }
        }
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
        output = g_strdup_printf ("%db", size);

    return output;
} /* format_size */

static gboolean
check_download_space (RCDTransaction *transaction, GError **err)
{
    gsize block_size;
    gsize avail_blocks;
    struct statvfs vfs_info;
    const char *cache_dir = rcd_prefs_get_cache_dir ();

    /* nothing to download... */
    if (!transaction->total_download_size)
        return TRUE;

    if (!g_file_test (cache_dir, G_FILE_TEST_EXISTS))
        rc_mkdir (cache_dir, 0755);

    if (statvfs (rcd_prefs_get_cache_dir (), &vfs_info))
        return FALSE;
    block_size = vfs_info.f_frsize;
    avail_blocks = vfs_info.f_bavail;

    if (transaction->total_download_size / block_size + 1 > avail_blocks) {
        g_set_error (err, RCD_TRANSACTION_ERROR_DOMAIN,
                     RCD_TRANSACTION_ERROR_DOWNLOAD,
                     "Insufficient disk space: %s needed in %s",
                     format_size (transaction->total_download_size),
                     rcd_prefs_get_cache_dir ());

        return FALSE;
    }
    else
        return TRUE;
} /* check_download_space */

static void
transfer_done_cb (RCDTransferPool  *pool,
                  RCDTransferError  err,
                  RCDTransaction   *transaction)
{
    g_hash_table_remove (abortable_transactions,
                         transaction->download_pending);

    if (!err) {
        if (transaction->flags == RCD_TRANSACTION_FLAGS_DOWNLOAD_ONLY)
            rcd_transaction_finished (transaction, NULL);
        else
            rcd_transaction_verification (transaction);
    }
    else {
        rcd_transaction_failed (transaction,
                                transaction->download_pending,
                                rcd_transfer_error_to_string (err));
    }
}

static void
rcd_transaction_download (RCDTransaction *transaction)
{
    GError *err = NULL;

    /*
     * This function fills out the packages_to_download and
     * total_download_size fields of the RCDTransaction.
     */
    if (!get_packages_to_download (transaction, &err))
        goto ERROR;

    if (transaction->packages_to_download) {
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
        rcd_fetch_packages (transaction->pool,
                            transaction->packages_to_download);
        rcd_transfer_pool_set_expected_size (transaction->pool,
                                             transaction->total_download_size);
        g_signal_connect (transaction->pool, "transfer_done",
                          G_CALLBACK (transfer_done_cb), transaction);
        rcd_transfer_pool_begin (transaction->pool);
    }
    else {
        rcd_pending_begin (transaction->download_pending);
        rcd_pending_finished (transaction->download_pending, 0);

        if (transaction->flags == RCD_TRANSACTION_FLAGS_DOWNLOAD_ONLY)
            rcd_transaction_finished (transaction, NULL);
        else
            rcd_transaction_verification (transaction);
    }

    return;

ERROR:

    rcd_transaction_failed (transaction,
                            err->code == RCD_TRANSACTION_ERROR_DOWNLOAD ?
                            transaction->download_pending :
                            transaction->transaction_pending,
                            err->message);
    g_error_free (err);
}

void
rcd_transaction_begin (RCDTransaction *transaction)
{
    g_return_if_fail (RCD_IS_TRANSACTION (transaction));

    rcd_transaction_emit_transaction_started (transaction);

    if (!transaction->install_packages && !transaction->remove_packages) {
        rcd_transaction_finished (transaction, "No action required.");
        return;
    }

    rcd_transaction_download (transaction);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

gboolean
rcd_transaction_check_package_integrity (const char *filename)
{
    RCWorld *world;
    RCPackman *packman;
    RCPackage *file_package = NULL;
    RCVerificationSList *vers = NULL, *iter;
    gboolean ret = FALSE;

    world = rc_get_world ();
    packman = rc_world_get_packman (world);

    file_package = rc_packman_query_file (packman, filename);
    file_package->package_filename = g_strdup (filename);

    /* Query failed, so it is a very hosed package. */
    if (!file_package)
        goto out;

    /* Verify file size and md5sum */
    vers = rc_packman_verify (packman, file_package,
                              RC_VERIFICATION_TYPE_SIZE |
                              RC_VERIFICATION_TYPE_MD5);

    if (rc_packman_get_error (packman)) {
        rc_debug (RC_DEBUG_LEVEL_WARNING, "Can't verify integrity of '%s': %s",
                  g_quark_to_string (RC_PACKAGE_SPEC (file_package)->nameq),
                  rc_packman_get_reason (packman));
        goto out;
    }

    for (iter = vers; iter; iter = iter->next) {
        RCVerification *ver = iter->data;

        if (ver->status != RC_VERIFICATION_STATUS_PASS) {
            rc_debug (RC_DEBUG_LEVEL_WARNING,
                      "Can't verify integrity of '%s', %s check failed",
                      g_quark_to_string (file_package->spec.nameq),
                      rc_verification_type_to_string (ver->type));
     
            goto out;
        }
    }

    ret = TRUE;

out:
    if (file_package)
        rc_package_unref (file_package);

    rc_verification_slist_free (vers);

    return ret;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static RCDTransaction *
get_transaction_from_id (int download_id)
{
    RCDPending *pending;

    if (!abortable_transactions)
        return NULL;

    pending = rcd_pending_lookup_by_id (download_id);

    if (!pending)
        return NULL;

    return g_hash_table_lookup (abortable_transactions, pending);
} /* get_transaction_from_id */

gboolean
rcd_transaction_is_valid (int download_id)
{
    return get_transaction_from_id (download_id) != NULL;
}

static gboolean
check_install_auth (RCDTransaction *transaction, RCDIdentity *identity)
{
    RCPackageSList *iter;
    gboolean install = FALSE;
    gboolean upgrade = FALSE;
    RCDPrivileges req_priv;
    gboolean approved;

    if (!transaction->install_packages)
        return TRUE;

    for (iter = transaction->install_packages;
         iter && !install && !upgrade;
         iter = iter->next)
    {
        RCPackage *p = (RCPackage *) iter->data;

        if (rc_world_find_installed_version (transaction->world, p))
            upgrade = TRUE;
        else
            install = TRUE;
    }

    if (upgrade) {
        req_priv = rcd_privileges_from_string ("upgrade");
        approved = rcd_identity_approve_action (identity, req_priv);

        if (!approved)
            return FALSE;
    }

    if (install) {
        req_priv = rcd_privileges_from_string ("install");
        approved = rcd_identity_approve_action (identity, req_priv);
    
        if (!approved)
            return FALSE;
    }

    return TRUE;
} /* check_install_auth */

int
rcd_transaction_abort (int download_id, RCDIdentity *identity)
{
    RCDTransaction *transaction;

    transaction = get_transaction_from_id (download_id);

    if (!transaction)
        return 0;

    /* Check our permissions to abort this download */
    if (!check_install_auth (transaction, identity))
        return -1;

    rcd_transfer_pool_abort (transaction->pool);

    return 1;
} /* rcd_transaction_abort */

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

#if 0
static xmlNode *
manifest_xml_node(RCPackage  *new_pkg,
                  RCPackage  *old_pkg,
                  const char *action)
{
    xmlNode *node, *pkgnode;
    char *tmp = NULL;
    RCPackageUpdate *update;

    node = xmlNewNode (NULL, "manifest");

    tmp = g_strdup_printf (
        "%s", new_pkg->channel ? rc_channel_get_id (new_pkg->channel) : "");
    xmlNewTextChild (node, NULL, "cid", tmp);
    g_free (tmp);

    xmlNewTextChild (node, NULL, "action", action);

    pkgnode = xmlNewChild (node, NULL, "package", NULL);

    xmlNewTextChild (pkgnode, NULL, "name",
                     g_quark_to_string (new_pkg->spec.nameq));

    tmp = g_strdup_printf ("%d", new_pkg->spec.epoch);
    xmlNewTextChild (pkgnode, NULL, "epoch", tmp);
    g_free (tmp);

    xmlNewTextChild(pkgnode, NULL, "version", new_pkg->spec.version);
    xmlNewTextChild(pkgnode, NULL, "release", new_pkg->spec.release);

    update = rc_package_get_latest_update (new_pkg);
    if (update) {
        tmp = g_strdup_printf ("%d", update->package_size);
        xmlNewTextChild (pkgnode, NULL, "size", tmp);
        g_free (tmp);

        tmp = g_strdup_printf ("%d", update->hid);
        xmlNewTextChild (pkgnode, NULL, "hid", tmp);
        g_free (tmp);

        if (new_pkg->channel) {
            xmlNewTextChild (pkgnode, NULL, "channel_id",
                             rc_channel_get_id (new_pkg->channel));
        }

        if (update->package_url)
            xmlNewTextChild (pkgnode, NULL, "url", update->package_url);
    }

    if (old_pkg) {
        pkgnode = xmlNewChild (node, NULL, "oldpackage", NULL);

        xmlNewTextChild (pkgnode, NULL, "name",
                         g_quark_to_string (new_pkg->spec.nameq));

        tmp = g_strdup_printf ("%d", old_pkg->spec.epoch);
        xmlNewTextChild (pkgnode, NULL, "epoch", tmp);
        g_free (tmp);

        xmlNewTextChild (pkgnode, NULL, "version", old_pkg->spec.version);
        xmlNewTextChild (pkgnode, NULL, "release", old_pkg->spec.release);
    }

    return node;
} /* manifest_xml_node */

static xmlChar *
transaction_xml (RCDTransactionStatus *status,
                 gboolean              successful,
                 const char           *message,
                 int                  *bytes)
{
    xmlDoc *doc;
    xmlNode *root;
    char *tmp;
    RCPackageSList *iter;
    xmlChar *xml_string;

    doc = xmlNewDoc ("1.0");
    root = xmlNewNode (NULL, "transaction");
    xmlDocSetRootElement (doc, root);

    if (status->name)
        xmlNewTextChild (root, NULL, "name", status->name);

    xmlNewTextChild (root, NULL, "client_id", status->client_id);
    xmlNewTextChild (root, NULL, "client_version", status->client_version);
    xmlNewTextChild (root, NULL, "mid", rcd_prefs_get_mid ());
    xmlNewTextChild (root, NULL, "distro", rc_distro_get_target ());

    xmlNewTextChild (root, NULL, "dry_run", 
                     status->flags & RCD_TRANSACTION_FLAGS_DRY_RUN ?
                     "1" : "0");

    tmp = g_strdup_printf ("%ld", status->start_time);
    xmlNewTextChild (root, NULL, "start_time", tmp);
    g_free (tmp);

    tmp = g_strdup_printf ("%ld", time (NULL));
    xmlNewTextChild (root, NULL, "end_time", tmp);
    g_free (tmp);

    xmlNewTextChild (root, NULL, "successful", successful ? "1" : "0");
    if (message)
        xmlNewTextChild (root, NULL, "message", message);

    for (iter = status->install_packages; iter; iter = iter->next) {
        RCPackage *p = iter->data;
        RCPackage *sys_pkg;
        const char *action;
        xmlNode *n;

        sys_pkg = rc_world_find_installed_version (rc_get_world (), p);

        if (sys_pkg)
            action = "update";
        else
            action = "install";

        n = manifest_xml_node (p, sys_pkg, action);

        xmlAddChild(root, n);
    }

    for (iter = status->remove_packages; iter; iter = iter->next) {
        RCPackage *p = iter->data;
        xmlNode *n;

        n = manifest_xml_node (p, NULL, "remove");

        xmlAddChild(root, n);
    }

    xmlDocDumpMemory(doc, &xml_string, bytes);
            
    return xml_string;
} /* transaction_xml */

static void
transaction_sent (RCDTransfer *t, gpointer user_data)
{
    RCDTransactionStatus *status = user_data;
    RCDTransferProtocolHTTP *protocol;

    if (rcd_transfer_get_error (t))
        goto cleanup;

    g_assert (strcmp (t->protocol->name, "http") == 0);

    protocol = (RCDTransferProtocolHTTP *) t->protocol;

    /* Not a g_free() because this is an xmlChar * */
    free (protocol->request_body);

cleanup:
    rcd_transaction_status_unref (status);

    g_object_unref (t);
} /* transaction_sent */

static void
rcd_transaction_send_log (RCDTransactionStatus *status,
                          gboolean              successful,
                          const char           *message)
{
    xmlChar *xml_string;
    int bytes;
    char *url;
    RCDTransfer *t;
    RCDTransferProtocolHTTP *protocol;

    url = g_strdup_printf ("%s/log.php", rcd_prefs_get_host ());

    t = rcd_transfer_new (url, 0, NULL);

    g_free (url);

    if (!t->protocol || strcmp (t->protocol->name, "http") != 0) {
        rc_debug (RC_DEBUG_LEVEL_WARNING, "Invalid log URL: %s", url);
        g_object_unref (t);
        return;
    }

    protocol = (RCDTransferProtocolHTTP *) t->protocol;

    rcd_transfer_protocol_http_set_method (protocol, SOUP_METHOD_POST);

    xml_string = transaction_xml (status, successful, message, &bytes);

    rcd_transfer_protocol_http_set_request_body (
        protocol, xml_string, bytes);

    g_signal_connect (t, "file_done", 
                      G_CALLBACK (transaction_sent),
                      rcd_transaction_status_ref (status));

    rcd_transfer_begin (t);
} /* rcd_transaction_send_log */
    
/*
 * This function is rather evil, but we need it to fake an
 * RCDTransactionStatus for things like dependency failures in autopull,
 * where we don't have one of these structures.
 */
void
rcd_transaction_log_to_server (const char         *name,
                               RCPackageSList     *install_packages,
                               RCPackageSList     *remove_packages,
                               RCDTransactionFlags flags,
                               const char         *client_id,
                               const char         *client_version,
                               gboolean            successful,
                               const char         *message)
{
    RCDTransactionStatus *status;

    if (!rcd_prefs_get_premium ())
        return;

    status = g_new0 (RCDTransactionStatus, 1);
    status->refs = 1;
    status->name = g_strdup (name);
    status->install_packages =
        g_slist_copy (rc_package_slist_ref (install_packages));
    status->remove_packages =
        g_slist_copy (rc_package_slist_ref (remove_packages));
    status->flags = flags;
    status->client_id = g_strdup (client_id);
    status->client_version = g_strdup (client_version);
    status->start_time = time (NULL);

    rcd_transaction_send_log (status, successful, message);

    rcd_transaction_status_unref (status);
} /* rcd_transaction_log_to_server */
#endif

void
rcd_transaction_lock (void)
{
    g_return_if_fail (transaction_lock == FALSE);

    transaction_lock = TRUE;
}

void
rcd_transaction_unlock (void)
{
    g_return_if_fail (transaction_lock == TRUE);

    transaction_lock = FALSE;
}

gboolean
rcd_transaction_is_locked (void)
{
    return transaction_lock;
}
