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
#ifdef HAVE_STATVFS
#include <sys/statvfs.h>
#endif

#include "rcd-fetch.h"
#include "rcd-log.h"
#include "rcd-pending.h"
#include "rcd-prefs.h"
#include "rcd-shutdown.h"
#include "rcd-transact-log.h"

typedef struct _RCDTransactionStatus RCDTransactionStatus;

struct _RCDTransactionStatus {
    RCWorld *world;
    RCPackman *packman;

    RCPackageSList *install_packages;
    RCPackageSList *remove_packages;

    /* Don't actually transact, just go through the motions */
    gboolean dry_run;

    RCPackageSList *packages_to_download;

    RCDPending *pending;
    int package_download_id;

    gsize total_download_size;
    gsize current_download_size;

    int total_transaction_steps;

    char *client_id;
    char *client_version;
    char *client_host;
    char *client_user;

    char **log_tid;
};

static gboolean transaction_lock = FALSE;

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
    const char *last;

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

    /* We don't want to push the same message multiple times */
    last = rcd_pending_get_latest_message (status->pending);
    if (!last || strcmp (msg, last) != 0)
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

static void
cleanup_after_transaction (RCDTransactionStatus *status)
{
    /*
     * If caching is turned off, we don't want to keep around the package
     * files on disk.
     */
    if (!rcd_prefs_get_cache_enabled ())
        cleanup_temp_package_files (status->packages_to_download);

    rc_package_slist_unref (status->install_packages);
    rc_package_slist_unref (status->remove_packages);
    rc_package_slist_unref (status->packages_to_download);
    g_object_unref (status->pending);
    g_free (status->client_id);
    g_free (status->client_version);
    g_free (status->client_host);
    g_free (status->client_user);
    
    g_free (status);
        
    /* Allow shutdowns again. */
    rcd_shutdown_allow ();
} /* cleanup_after_transaction */    

static void
update_log (RCDTransactionStatus *status)
{
    RCPackageSList *iter;

    for (iter = status->install_packages; iter; iter = iter->next) {
        RCPackage *new_p = iter->data;
        RCPackage *old_p;
        RCDLogEntry *log_entry;

        log_entry = rcd_log_entry_new (status->client_host,
                                       status->client_user);

        old_p = rc_world_get_package (rc_get_world (),
                                      RC_WORLD_SYSTEM_PACKAGES,
                                      g_quark_to_string (new_p->spec.nameq));

        if (old_p)
            rcd_log_entry_set_upgrade (log_entry, old_p, new_p);
        else
            rcd_log_entry_set_install (log_entry, new_p);

        rcd_log (log_entry);
        rcd_log_entry_free (log_entry);
    }

    for (iter = status->remove_packages; iter; iter = iter->next) {
        RCPackage *p = iter->data;
        RCDLogEntry *log_entry;

        log_entry = rcd_log_entry_new (status->client_host,
                                       status->client_user);
        rcd_log_entry_set_remove (log_entry, p);
        rcd_log (log_entry);
        rcd_log_entry_free (log_entry);
    }
} /* update_log */

static void
fail_transaction (RCDTransactionStatus *status, const char *msg)
{
    char *pending_msg;

    rc_debug (RC_DEBUG_LEVEL_WARNING, "Transaction failed: %s", msg);

    pending_msg = g_strdup_printf ("failed:%s", msg);
    rcd_pending_add_message (status->pending, pending_msg);
    g_free (pending_msg);

    rcd_pending_fail (status->pending, -1, msg);

    if (!status->dry_run && status->log_tid) 
        rcd_transact_log_send_success (status->log_tid, FALSE, msg);
} /* fail_transaction */

static gboolean
run_transaction(gpointer user_data)
{
    RCDTransactionStatus *status = user_data;

    if (rcd_transaction_is_locked ()) {
        fail_transaction (status,
                          "Another transaction is already in progress");
        goto cleanup;
    }

    rcd_transaction_lock ();

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
                         status->remove_packages,
                         ! status->dry_run);

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
        fail_transaction (status, rc_packman_get_reason (status->packman));
        goto unlock_and_cleanup;
    }
    else {
        if (!status->dry_run) {
            update_log (status);
            
            if (status->log_tid)
                rcd_transact_log_send_success (status->log_tid, TRUE, NULL);
        }
    }

    /* Update the list of system packages */
    if (! status->dry_run)
        rc_world_get_system_packages (rc_get_world ());

unlock_and_cleanup:
    rcd_transaction_unlock ();

cleanup:
    cleanup_after_transaction (status);

    return FALSE;
} /* run_transaction */

static void
verify_packages (RCDTransactionStatus *status)
{
    RCPackageSList *iter;

    rc_verification_set_keyring (SHAREDIR "/rcd.gpg");

    for (iter = status->install_packages; iter; iter = iter->next) {
        RCPackage *package = iter->data;
        char *msg;
        RCVerificationSList *vers;
        RCVerificationStatus worst_status = RC_VERIFICATION_STATUS_PASS;
        GSList *v;

        msg = g_strconcat ("verify:",
                           g_quark_to_string (package->spec.nameq), NULL);
        rcd_pending_add_message (status->pending, msg);
        g_free (msg);

        vers = rc_packman_verify (
            status->packman, package, RC_VERIFICATION_TYPE_ALL);
        for (v = vers; v; v = v->next) {
            RCVerification *ver = v->data;

            if (worst_status > ver->status)
                worst_status = ver->status;
        }

        rc_verification_slist_free (vers);

        if (worst_status == RC_VERIFICATION_STATUS_FAIL) {
            rc_debug (RC_DEBUG_LEVEL_MESSAGE,
                      "Verification of '%s' failed",
                      g_quark_to_string (package->spec.nameq));
            msg = g_strdup_printf ("failed:Verification of '%s' failed",
                                   g_quark_to_string (package->spec.nameq));
            rcd_pending_add_message (status->pending, msg);
            rcd_pending_fail (status->pending, -1, msg);
            g_free (msg);

            if (!status->dry_run && status->log_tid) {
                msg = g_strdup_printf (
                    "Verification of '%s' failed",
                    g_quark_to_string (package->spec.nameq));
                rcd_transact_log_send_success (status->log_tid, FALSE, msg);
                g_free (msg);
            }

            cleanup_after_transaction (status);
            return;
        }
        else if (worst_status == RC_VERIFICATION_STATUS_UNDEF) {
            rc_debug (RC_DEBUG_LEVEL_MESSAGE,
                      "Verification of '%s' was inconclusive",
                      g_quark_to_string (package->spec.nameq));

            if (rcd_prefs_get_require_verified_packages ()) {
                msg = g_strdup_printf (
                    "failed:Verification of '%s' was inconclusive",
                    g_quark_to_string (package->spec.nameq));
                rcd_pending_add_message (status->pending, msg);
                rcd_pending_fail (status->pending, -1, msg);
                g_free (msg);

                if (!status->dry_run && status->log_tid) {
                    msg = g_strdup_printf (
                        "Verification of '%s' failed",
                        g_quark_to_string (package->spec.nameq));
                    rcd_transact_log_send_success (
                        status->log_tid, FALSE, msg);
                    g_free (msg);
                }

                cleanup_after_transaction (status);
                return;
            }
        }
    }

    g_idle_add (run_transaction, status);
} /* verify_packages */

static void
download_completed (gboolean    successful,
                    const char *error_message,
                    gpointer    user_data)
{
    RCDTransactionStatus *status = user_data;
    char *msg;

    if (successful) {
        verify_packages (user_data);
        return;
    }

    /* A NULL error message indicates that it was cancelled, not a failure */
    if (!error_message) {
        rcd_pending_abort (status->pending, -1);
        error_message = "Cancelled by user";
    }
    else {
        msg = g_strdup_printf ("failed:Download failed - %s", error_message);
        rcd_pending_add_message (status->pending, msg);
        rcd_pending_fail (status->pending, -1, msg);
        g_free (msg);
    }

    if (!status->dry_run && status->log_tid) {
        msg = g_strdup_printf ("Download failed - %s", error_message);
        rcd_transact_log_send_success (status->log_tid, FALSE, msg);
        g_free (msg);
    }

    cleanup_after_transaction (status);
} /* download_completed */

static void
update_download_progress (gsize size, gpointer user_data)
{
    RCDTransactionStatus *status = user_data;

    status->current_download_size += size;

    rcd_pending_update_by_size (status->pending,
                                status->current_download_size,
                                status->total_download_size);    
} /* update_download_progress */

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
check_download_space (gsize download_size)
{
    gsize block_size;
    gsize avail_blocks;

#ifdef HAVE_STATVFS
    struct statvfs vfs_info;

    statvfs (rcd_prefs_get_cache_dir (), &vfs_info);
    block_size = vfs_info.f_frsize;
    avail_blocks = vfs_info.f_bavail;
#else
    struct statfs fs_info;

    statfs (rcd_prefs_get_cache_dir (), &fs_info);
    block_size = fs_info.f_bsize;
    avail_blocks = fs_info.f_bavail;
#endif

    if (download_size / block_size + 1 > avail_blocks)
        return FALSE;
    else
        return TRUE;
} /* check_download_space */

static int
download_packages (RCPackageSList *packages, RCDTransactionStatus *status)
{
    RCPackageSList *iter;

    status->total_download_size = 0;
    status->packages_to_download = NULL;

    for (iter = packages; iter; iter = iter->next) {
        RCPackage *package = iter->data;

        if (package->package_filename) {
            if (!g_file_test (package->package_filename, G_FILE_TEST_EXISTS)) {
                g_free (package->package_filename);
                package->package_filename = NULL;
            }
        }

        if (!package->package_filename) {
            status->packages_to_download = g_slist_prepend (
                status->packages_to_download, rc_package_ref (package));
            status->total_download_size +=
                rc_package_get_latest_update (package)->package_size;
        }
    }

    if (!status->packages_to_download)
        return 0;

    if (!check_download_space (status->total_download_size)) {
        char *msg;

        msg = g_strdup_printf ("Insufficient disk space: %s needed in %s",
                               format_size (status->total_download_size),
                               rcd_prefs_get_cache_dir ());
        fail_transaction (status, msg);
        g_free (msg);

        return -1;
    }

    rcd_pending_add_message (status->pending, "download");
    rcd_pending_update (status->pending, 0.0);

    status->packages_to_download =
        g_slist_reverse (status->packages_to_download);

    status->package_download_id = rcd_fetch_packages (
        status->packages_to_download, 
        update_download_progress,
        download_completed,
        status);

    return g_slist_length (status->packages_to_download);
} /* download_packages */

int
rcd_transaction_begin (RCWorld        *world,
                       RCPackageSList *install_packages,
                       RCPackageSList *remove_packages,
                       gboolean        dry_run,
                       const char     *client_id,
                       const char     *client_version,
                       const char     *client_host,
                       const char     *client_user)
{
    RCDTransactionStatus *status;

    status = g_new0 (RCDTransactionStatus, 1);
    status->world = world;
    status->packman = rc_world_get_packman (world);
    status->install_packages = rc_package_slist_ref (install_packages);
    status->remove_packages = rc_package_slist_ref (remove_packages);
    status->dry_run = dry_run;
    status->client_id = g_strdup (client_id);
    status->client_version = g_strdup (client_version);
    status->client_host = g_strdup (client_host);
    status->client_user = g_strdup (client_user);

    status->pending = rcd_pending_new ("Package Transaction");
    g_object_set_data (G_OBJECT (status->pending), "status", status);
    rcd_pending_begin (status->pending);

    /*
     * We don't want to allow the shutting down of the daemon while we're
     * in the middle of a transaction.
     */
    rcd_shutdown_block ();

    /* If we're in premium mode, send a log of the transaction to the server */
    if (rcd_prefs_get_premium ()) {
        status->log_tid = rcd_transact_log_send_transaction (
            status->install_packages,
            status->remove_packages,
            status->client_id, status->client_version);
    }

    /*
     * If we have to download files, start the download.  Otherwise,
     * schedule the transaction
     *
     * If there's an error, it'll be set in download_packages(), and
     * return a negative value (and not triggering the run_transaction()
     * call).
     */
    if (!download_packages (status->install_packages, status))
        g_idle_add (run_transaction, status);

    return rcd_pending_get_id (status->pending);
} /* rcd_transaction_begin */

static RCDTransactionStatus *
get_transaction_from_id (int transaction_id)
{
    RCDPending *pending;
    RCDTransactionStatus *status;

    pending = rcd_pending_lookup_by_id (transaction_id);

    if (!pending)
        return NULL;

    status = g_object_get_data (G_OBJECT (pending), "status");
    if (!status)
        return NULL;

    return status;
} /* get_transaction_from_id */

gboolean
rcd_transaction_is_valid (int transaction_id)
{
    return get_transaction_from_id (transaction_id) != NULL;
}

RCPackageSList *
rcd_transaction_get_install_packages (int transaction_id)
{
    RCDTransactionStatus *status;

    status = get_transaction_from_id (transaction_id);

    g_return_val_if_fail (status, NULL);

    /* FIXME: Should we ref here? */
    return status->install_packages;
} /* rcd_transaction_get_install_packages */

int
rcd_transaction_get_package_download_id (int transaction_id)
{
    RCDTransactionStatus *status;

    status = get_transaction_from_id (transaction_id);

    g_return_val_if_fail (status, 0);

    return status->package_download_id;
} /* rcd_transaction_get_package_download_id */

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
