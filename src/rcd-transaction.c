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
#include "rcd-pending.h"
#include "rcd-prefs.h"
#include "rcd-rollback.h"
#include "rcd-shutdown.h"
#include "rcd-transfer.h"
#include "rcd-transfer-http.h"

typedef struct _RCDTransactionStatus RCDTransactionStatus;

struct _RCDTransactionStatus {
    int refs;

    char *name;

    RCWorld *world;
    RCPackman *packman;

    RCPackageSList *install_packages;
    RCPackageSList *remove_packages;

    RCDTransactionFlags flags;

    RCPackageSList *packages_to_download;

    RCDPending *download_pending;
    RCDPending *transaction_pending;
    RCDPending *transaction_step_pending;

    gsize total_download_size;
    gsize current_download_size;

    int total_transaction_steps;

    int transaction_size;

    char *client_id;
    char *client_version;
    char *client_host;
    RCDIdentity *identity;

    time_t start_time;

    char *temp_repack_dir;
};

static gboolean transaction_lock = FALSE;

static RCDTransactionStatus *
rcd_transaction_status_ref (RCDTransactionStatus *status)
{
    g_return_val_if_fail (status, NULL);

    status->refs++;

    return status;
}

static void
rcd_transaction_status_unref (RCDTransactionStatus *status)
{
    g_return_if_fail (status);

    status->refs--;

    if (status->refs == 0) {
        g_free (status->name);
        rc_package_slist_unref (status->install_packages);
        rc_package_slist_unref (status->remove_packages);
        rc_package_slist_unref (status->packages_to_download);
        g_free (status->client_id);
        g_free (status->client_version);
        g_free (status->client_host);
        g_free (status->temp_repack_dir);
        rcd_identity_free (status->identity);

        if (status->download_pending) {
            g_object_set_data (G_OBJECT (status->download_pending),
                               "status", NULL);
            g_object_unref (status->download_pending);
        }

        if (status->transaction_pending)
            g_object_unref (status->transaction_pending);

        if (status->transaction_step_pending)
            g_object_unref (status->transaction_step_pending);
    
        g_free (status);
    }
} /* rcd_transaction_status_unref */

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

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
        "%d", new_pkg->channel ? rc_channel_get_id (new_pkg->channel) : 0);
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
            tmp = g_strdup_printf ("%d", rc_channel_get_id (new_pkg->channel));
            xmlNewTextChild (pkgnode, NULL, "channel_id", tmp);
            g_free (tmp);
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
    status->install_packages = rc_package_slist_ref (install_packages);
    status->remove_packages = rc_package_slist_ref (remove_packages);
    status->flags = flags;
    status->client_id = g_strdup (client_id);
    status->client_version = g_strdup (client_version);
    status->start_time = time (NULL);

    rcd_transaction_send_log (status, successful, message);

    rcd_transaction_status_unref (status);
} /* rcd_transaction_log_to_server */

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
    const char *last;

    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Transaction step.  seqno %d", seqno);

    rcd_pending_update_by_size (status->transaction_pending, seqno - 1,
                                status->total_transaction_steps);

    status->transaction_size = 0;

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
    last = rcd_pending_get_latest_message (status->transaction_pending);
    if (!last || strcmp (msg, last) != 0)
        rcd_pending_add_message (status->transaction_pending, msg);

    g_free (msg);
} /* transact_step_cb */

static void
transact_progress_cb(RCPackman *packman,
                     int amount,
                     int total,
                     RCDTransactionStatus *status)
{
    rc_debug (RC_DEBUG_LEVEL_INFO,
              "Transaction progress.  %d of %d", amount, total);

    if (status->transaction_size == 0) {
        if (rcd_pending_get_status (status->transaction_step_pending) ==
            RCD_PENDING_STATUS_PRE_BEGIN)
            rcd_pending_begin (status->transaction_step_pending);
        else
            rcd_pending_update (status->transaction_step_pending, 0);
    }

    if (amount > status->transaction_size) {
        rcd_pending_update_by_size (status->transaction_step_pending,
                                    amount, total);
    }
} /* transact_progress_cb */

static void
transact_done_cb(RCPackman *packman,
                 RCDTransactionStatus *status)
{
    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Transaction done");

    rcd_pending_finished (status->transaction_pending, 0);
    if (rcd_pending_get_status (status->transaction_step_pending) !=
        RCD_PENDING_STATUS_PRE_BEGIN)
        rcd_pending_finished (status->transaction_step_pending, 0);
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
    if (!rcd_prefs_get_cache_enabled () &&
        status->flags != RCD_TRANSACTION_FLAGS_DOWNLOAD_ONLY)
        cleanup_temp_package_files (status->packages_to_download);

    rcd_transaction_status_unref (status);

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
                                       status->identity->username);

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
                                       status->identity->username);
        rcd_log_entry_set_remove (log_entry, p);
        rcd_log (log_entry);
        rcd_log_entry_free (log_entry);
    }
} /* update_log */

static void
fail_transaction (RCDTransactionStatus *status,
                  RCDPending           *pending,
                  const char           *msg)
{
    rc_debug (RC_DEBUG_LEVEL_WARNING, "Transaction failed: %s", msg);

    rcd_pending_fail (pending, -1, msg);

    if (rcd_prefs_get_premium ())
        rcd_transaction_send_log (status, FALSE, msg);

    cleanup_after_transaction (status);
} /* fail_transaction */

static void
add_rollback_packages (RCDTransactionStatus *status)
{
    RCPackageSList *packages = NULL;
    GDir *dir;
    GError *error = NULL;
    const char *filename;
    char *repackage_dir;
    gboolean dirty = FALSE;

    dir = g_dir_open (status->temp_repack_dir, 0, &error);

    if (!dir) {
        rc_debug (RC_DEBUG_LEVEL_WARNING, "Unable to open '%s': %s",
                  status->temp_repack_dir, error->message);
        return;
    }

    repackage_dir = g_strconcat (rcd_prefs_get_cache_dir (),
                                 "/repackage", NULL);

    while ((filename = g_dir_read_name (dir))) {
        char *fn = g_strconcat (status->temp_repack_dir, "/", filename, NULL);
        char *newfn;
        RCPackage *p = rc_packman_query_file (status->packman, fn);

        if (!p) {
            rc_debug (RC_DEBUG_LEVEL_WARNING,
                      "Invalid package file in repack dir: %s", fn);
            g_free (fn);
            dirty = TRUE;
            continue;
        }

        /* Move the file from the temporary directory */
        newfn = g_strconcat (repackage_dir, "/", filename, NULL);
        if (rename (fn, newfn) < 0) {
            rc_debug (RC_DEBUG_LEVEL_WARNING, "Unable to move '%s' to '%s'",
                      fn, newfn);
            g_free (newfn);
            dirty = TRUE;
        }
        else {
            p->package_filename = newfn;

            /*
             * More efficient to add the packages as a list, so we don't sync
             * to disk every time.
             */
            packages = g_slist_prepend (packages, p);
        }

        g_free (fn);
    }

    g_dir_close (dir);
    g_free (repackage_dir);

    rcd_rollback_add_package_slist (packages);
    rc_package_slist_unref (packages);

    if (!dirty)
        rc_rmdir (status->temp_repack_dir);
} /* add_rollback_packages */

static gboolean
run_transaction(gpointer user_data)
{
    RCDTransactionStatus *status = user_data;
    gboolean repackage;
    int flags = 0;

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

    repackage = (rc_packman_get_capabilities (status->packman) &
                 RC_PACKMAN_CAP_REPACKAGING && rcd_prefs_get_repackage ());

    if (repackage) {
        char *repackage_dir;

        repackage_dir = g_strconcat (rcd_prefs_get_cache_dir (),
                                     "/repackage", NULL);

        if (!g_file_test (repackage_dir, G_FILE_TEST_EXISTS) &&
            rc_mkdir (repackage_dir, 0755) < 0)
        {
            rc_debug (RC_DEBUG_LEVEL_WARNING, "Couldn't create '%s'",
                      repackage_dir);
        }
        else {
            status->temp_repack_dir = g_strconcat (repackage_dir,
                                                   "/repack-XXXXXX", NULL);
            if (!rc_mkdtemp (status->temp_repack_dir)) {
                rc_debug (RC_DEBUG_LEVEL_WARNING, "Couldn't create '%s'",
                          status->temp_repack_dir);
            }
            else {
                rc_packman_set_repackage_dir (status->packman,
                                              status->temp_repack_dir);
                flags |= RC_TRANSACT_FLAG_REPACKAGE;
            }
        }

        g_free (repackage_dir);
    }

    /*
     * RPM has a bug (surprise!) where it will write out a 0 byte file
     * when repackaging a package with the no act flag.  So that's why
     * we're assigning RC_TRANSACT_FLAG_NO_ACT to flags instead of doing
     * a logical or.
     */
    if (status->flags == RCD_TRANSACTION_FLAGS_DRY_RUN)
        flags = RC_TRANSACT_FLAG_NO_ACT;

    rc_packman_transact (status->packman,
                         status->install_packages,
                         status->remove_packages,
                         flags);

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
        fail_transaction (status, status->transaction_pending,
                          rc_packman_get_reason (status->packman));
        rcd_transaction_unlock ();
        return FALSE;
    }
    else {
        if (status->flags != RCD_TRANSACTION_FLAGS_DRY_RUN) {
            update_log (status);

            if (repackage)
                add_rollback_packages (status);
        }

        if (rcd_prefs_get_premium ())
            rcd_transaction_send_log (status, TRUE, NULL);
    }

    /* Update the list of system packages */
    if (status->flags != RCD_TRANSACTION_FLAGS_DRY_RUN)
        rc_world_get_system_packages (rc_get_world ());

    rcd_transaction_unlock ();
    cleanup_after_transaction (status);

    return FALSE;
} /* run_transaction */

static void
verify_packages (RCDTransactionStatus *status)
{
    RCPackageSList *iter;

    /* Fire up the transaction pending */
    rcd_pending_begin (status->transaction_pending);

    if (rcd_transaction_is_locked ()) {
        fail_transaction (status, status->transaction_pending,
                          "Another transaction is already in progress");
        return;
    }

    rcd_transaction_lock ();

    rc_verification_set_keyring (SHAREDIR "/rcd.gpg");

    for (iter = status->install_packages; iter; iter = iter->next) {
        RCPackage *package = iter->data;
        char *msg;
        RCVerificationSList *vers;
        RCVerificationStatus worst_status = RC_VERIFICATION_STATUS_PASS;
        gboolean gpg_attempted = FALSE;
        GSList *v;

        /* Flush the glib main loop queue */
        while (g_main_pending ())
            g_main_iteration (TRUE);

        msg = g_strconcat ("verify:",
                           g_quark_to_string (package->spec.nameq), NULL);
        rcd_pending_add_message (status->transaction_pending, msg);
        g_free (msg);

        vers = rc_packman_verify (
            status->packman, package, RC_VERIFICATION_TYPE_ALL);

        if (rc_packman_get_error (status->packman)) {
            fail_transaction (status, status->transaction_pending,
                              rc_packman_get_reason (status->packman));
            
            goto failure;
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

            msg = g_strdup_printf ("Verification of '%s' failed",
                                   g_quark_to_string (package->spec.nameq));
            fail_transaction (status, status->transaction_pending, msg);
            g_free (msg);

            goto failure;
        }
        else if (worst_status == RC_VERIFICATION_STATUS_UNDEF ||
                 !gpg_attempted)
        {
            char *status_msg;
            gboolean is_trusted;

            if (!gpg_attempted) {
                msg = g_strdup_printf (
                    "Package '%s' is not signed",
                    g_quark_to_string (package->spec.nameq));
            }
            else {
                msg = g_strdup_printf (
                    "Unable to verify package signature for '%s'",
                    g_quark_to_string (package->spec.nameq));
            }

            rc_debug (RC_DEBUG_LEVEL_MESSAGE, msg);

            is_trusted = rcd_identity_approve_action (
                status->identity,
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
            rcd_pending_add_message (status->transaction_pending, status_msg);
            g_free (status_msg);

            if (!is_trusted && rcd_prefs_get_require_signed_packages ())
            {
                status_msg = g_strconcat (msg,
                                          "; verified package signatures "
                                          "are required for installation",
                                          NULL);
                fail_transaction (status, status->transaction_pending,
                                  status_msg);

                g_free (status_msg);
                g_free (msg);

                goto failure;
            }

            g_free (msg);
        }
    }

    g_idle_add (run_transaction, status);
    return;

failure:
    rcd_transaction_unlock ();
} /* verify_packages */

static void
download_completed (gboolean    successful,
                    const char *error_message,
                    gpointer    user_data)
{
    RCDTransactionStatus *status = user_data;
    char *msg;

    if (successful) {
        rcd_pending_finished (status->download_pending, 0);
        if (status->flags != RCD_TRANSACTION_FLAGS_DOWNLOAD_ONLY)
            verify_packages (user_data);
        else
            cleanup_after_transaction (status);

        return;
    }

    /* A NULL error message indicates that it was cancelled, not a failure */
    if (!error_message) {
        rcd_pending_abort (status->download_pending, -1);
        error_message = "Cancelled by user";
    }
    else {
        msg = g_strdup_printf ("failed:Download failed - %s", error_message);
        rcd_pending_fail (status->download_pending, -1, error_message);
        g_free (msg);
    }

    if (rcd_prefs_get_premium ())
    {
        msg = g_strdup_printf ("Download failed - %s", error_message);
        rcd_transaction_send_log (status, FALSE, msg);
        g_free (msg);
    }

    cleanup_after_transaction (status);
} /* download_completed */

static void
update_download_progress (gsize size, gpointer user_data)
{
    RCDTransactionStatus *status = user_data;

    status->current_download_size += size;

    rcd_pending_update_by_size (status->download_pending,
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
    struct statvfs vfs_info;

    statvfs (rcd_prefs_get_cache_dir (), &vfs_info);
    block_size = vfs_info.f_frsize;
    avail_blocks = vfs_info.f_bavail;

    if (download_size / block_size + 1 > avail_blocks)
        return FALSE;
    else
        return TRUE;
} /* check_download_space */

static gboolean
check_package_integrity (RCPackage *package, RCDTransactionStatus *status)
{
    RCPackage *file_package;
    RCVerificationSList *vers;
    gboolean inconclusive = FALSE;

    file_package = rc_packman_query_file (
        status->packman, package->package_filename);

    /* Query failed, so it is a very hosed package. */
    if (!file_package)
        return FALSE;

    /* Verify file size and md5sum on package */
    vers = rc_packman_verify (
        status->packman, package,
        RC_VERIFICATION_TYPE_SIZE | RC_VERIFICATION_TYPE_MD5);

    if (rc_packman_get_error (status->packman)) {
        rc_debug (RC_DEBUG_LEVEL_WARNING, "Can't verify integrity of '%s': %s",
                  g_quark_to_string (RC_PACKAGE_SPEC (package)->nameq),
                  rc_packman_get_reason (status->packman));
        return FALSE;
    }

    if (!vers) {
        /* Nothing to verify?  Probably a repackaged RPM, so we're okay. */
        return TRUE;
    }
    
    for (; vers; vers = vers->next) {
        RCVerification *ver = vers->data;

        if (ver->status == RC_VERIFICATION_STATUS_FAIL)
            return FALSE;
        else if (ver->status == RC_VERIFICATION_STATUS_PASS)
            inconclusive = FALSE;
    }

    /*
     * The check was inconclusive, so if we can download it again, we're
     * better safe than sorry and fail the thing.
     */
    if (inconclusive) {
        if (rc_package_get_latest_update (package))
            return FALSE;
        else
            return TRUE;
    }
    else
        return TRUE;
} /* check_package_integrity */

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
            else {
                if (!check_package_integrity (package, status)) {
                    RCDCacheEntry *entry;

                    entry = rcd_cache_lookup (rcd_cache_get_package_cache (),
                                              package->package_filename);
                    if (entry)
                        rcd_cache_entry_invalidate (entry);

                    /*
                     * We can't download another version of this package
                     * because it isn't in a channel, and therefore has
                     * nothing in its history section.
                     */
                    if (!rc_package_get_latest_update (package)) {
                        char *msg;

                        msg = g_strdup_printf ("%s is not a valid package",
                                               package->package_filename);
                        /* We begin the transaction pending just to fail it. */
                        rcd_pending_begin (status->transaction_pending);
                        fail_transaction (status, status->transaction_pending,
                                          msg);
                        g_free (msg);
                        g_free (package->package_filename);
                        package->package_filename = NULL;

                        return -1;
                    }

                    g_free (package->package_filename);
                    package->package_filename = NULL;
                }
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

    status->download_pending = rcd_pending_new ("Package download");
    g_object_set_data (G_OBJECT (status->download_pending), "status", status);

    rcd_pending_begin (status->download_pending);

    if (!check_download_space (status->total_download_size)) {
        char *msg;

        msg = g_strdup_printf ("Insufficient disk space: %s needed in %s",
                               format_size (status->total_download_size),
                               rcd_prefs_get_cache_dir ());
        fail_transaction (status, status->download_pending, msg);
        g_free (msg);

        return -1;
    }
    
    status->packages_to_download =
        g_slist_reverse (status->packages_to_download);

    rcd_fetch_packages (
        status->packages_to_download,
        rcd_pending_get_id (status->download_pending),
        update_download_progress,
        download_completed,
        status);

    return g_slist_length (status->packages_to_download);
} /* download_packages */

static gboolean
verify_only (gpointer user_data)
{
    RCDTransactionStatus *status = user_data;
    verify_packages (status);
    rcd_transaction_status_unref (status);
    return FALSE;
}

void
rcd_transaction_begin (const char          *name,
                       RCWorld             *world,
                       RCPackageSList      *install_packages,
                       RCPackageSList      *remove_packages,
                       RCDTransactionFlags  flags,
                       const char          *client_id,
                       const char          *client_version,
                       const char          *client_host,
                       RCDIdentity         *identity,
                       int                 *download_pending_id,
                       int                 *transaction_pending_id,
                       int                 *step_pending_id)
{
    RCDTransactionStatus *status;
    int download_count;

    status = g_new0 (RCDTransactionStatus, 1);
    status->refs = 1;
    status->name = g_strdup (name);
    status->world = world;
    status->packman = rc_world_get_packman (world);
    status->install_packages = rc_package_slist_ref (install_packages);
    status->remove_packages = rc_package_slist_ref (remove_packages);
    status->flags = flags;
    status->client_id = g_strdup (client_id);
    status->client_version = g_strdup (client_version);
    status->client_host = g_strdup (client_host);
    status->identity = rcd_identity_copy (identity);
    status->start_time = time (NULL);

    if (install_packages == NULL && remove_packages == NULL) {

        if (download_pending_id)
            *download_pending_id = -1;
        if (transaction_pending_id)
            *transaction_pending_id = -1;
        if (step_pending_id)
            *step_pending_id = -1;

        if (rcd_prefs_get_premium ())
            rcd_transaction_send_log (status, TRUE, "No action required.");

        rcd_transaction_status_unref (status);
        return;
    }

    /*
     * We don't want to allow the shutting down of the daemon while we're
     * in the middle of a transaction.
     */
    rcd_shutdown_block ();

    if (status->flags != RCD_TRANSACTION_FLAGS_DOWNLOAD_ONLY) {
        status->transaction_pending = rcd_pending_new ("Package transaction");
        status->transaction_step_pending =
            rcd_pending_new ("Package transaction step");
    }

    /*
     * If we have to download files, start the download.  Otherwise,
     * schedule the transaction
     *
     * If there's an error, it'll be set in download_packages(), and
     * return a negative value (and not triggering the run_transaction()
     * call).
     */
    rcd_transaction_status_ref (status);
    download_count = download_packages (status->install_packages, status);

    if (download_pending_id) {
        if (status->download_pending) {
            *download_pending_id = rcd_pending_get_id (
                status->download_pending);
        }
        else
            *download_pending_id = -1;
    }

    if (transaction_pending_id) {
        if (status->transaction_pending) {
            *transaction_pending_id =
                rcd_pending_get_id (status->transaction_pending);
        }
        else
            *transaction_pending_id = -1;
    }

    if (step_pending_id) {
        if (status->transaction_step_pending) {
            *step_pending_id =
                rcd_pending_get_id (status->transaction_step_pending);
        }
        else
            *step_pending_id = -1;
    }

    if (!download_count &&
        status->flags != RCD_TRANSACTION_FLAGS_DOWNLOAD_ONLY) {
        rcd_transaction_status_ref (status);
        g_idle_add (verify_only, status);
    }

    rcd_transaction_status_unref (status);
} /* rcd_transaction_begin */

static RCDTransactionStatus *
get_transaction_from_id (int download_id)
{
    RCDPending *pending;
    RCDTransactionStatus *status;

    pending = rcd_pending_lookup_by_id (download_id);

    if (!pending)
        return NULL;

    status = g_object_get_data (G_OBJECT (pending), "status");
    if (!status)
        return NULL;

    return status;
} /* get_transaction_from_id */

gboolean
rcd_transaction_is_valid (int download_id)
{
    return get_transaction_from_id (download_id) != NULL;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static gboolean
check_install_auth (RCDTransactionStatus *status, RCDIdentity *identity)
{
    RCPackageSList *iter;
    gboolean install = FALSE;
    gboolean upgrade = FALSE;
    RCDPrivileges req_priv;
    gboolean approved;

    if (!status->install_packages)
        return TRUE;

    for (iter = status->install_packages;
         iter && !install && !upgrade;
         iter = iter->next)
    {
        RCPackage *p = (RCPackage *) iter->data;

        if (rc_world_find_installed_version (status->world, p))
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
    RCDTransactionStatus *status;

    status = get_transaction_from_id (download_id);

    if (!status)
        return 0;

    if (!status->install_packages || rcd_transaction_is_locked ()) {
        /*
         * We can only abort downloads, so if we're not installing anything,
         * or we are in the middle of a transaction, we cannot abort it.
         */
        return 0;
    }

    /* Check our permissions to abort this download */
    if (!check_install_auth (status, identity))
        return -1;

    rcd_fetch_packages_abort (download_id);

    return 1;
} /* rcd_transaction_abort */

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

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
