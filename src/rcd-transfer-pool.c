/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-transfer-pool.c
 *
 * Copyright (C) 2002-2003 Ximian, Inc.
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
#include "rcd-transfer-pool.h"

#include <libredcarpet.h>

#include "rcd-marshal.h"
#include "rcd-prefs.h"

static GObjectClass *parent_class;

enum {
    TRANSFER_DONE,
    LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void
rcd_transfer_pool_finalize (GObject *obj)
{
    RCDTransferPool *pool = RCD_TRANSFER_POOL (obj);

    g_slist_foreach (pool->transfers, (GFunc) g_object_unref, NULL);
    g_slist_free (pool->transfers);

    if (pool->pending)
        g_object_unref (pool->pending);

    g_slist_free (pool->running_transfers);
    g_slist_free (pool->queued_transfers);

    if (parent_class->finalize)
        parent_class->finalize (obj);
}

static void
rcd_transfer_pool_transfer_done (RCDTransferPool *pool,
                                 RCDTransferError failing_err)
{
    /* Removes the ref added in rcd_transfer_pool_begin() */
    g_object_unref (pool);
}

static void
rcd_transfer_pool_class_init (RCDTransferPoolClass *klass)
{
    GObjectClass *obj_class = (GObjectClass *) klass;

    parent_class = g_type_class_peek_parent (klass);

    obj_class->finalize = rcd_transfer_pool_finalize;

    klass->transfer_done = rcd_transfer_pool_transfer_done;

    signals[TRANSFER_DONE] =
        g_signal_new ("transfer_done",
                      G_TYPE_FROM_CLASS (klass),
                      G_SIGNAL_RUN_FIRST,
                      G_STRUCT_OFFSET (RCDTransferPoolClass, transfer_done),
                      NULL, NULL,
                      rcd_marshal_VOID__INT,
                      G_TYPE_NONE, 1, G_TYPE_INT);
}

static void
rcd_transfer_pool_init (RCDTransferPool *pool)
{
    /* Create associated RCPending object */
    pool->pending = rc_pending_new (NULL);
}

GType
rcd_transfer_pool_get_type (void)
{
    static GType type = 0;

    if (! type) {
        static GTypeInfo type_info = {
            sizeof (RCDTransferPoolClass),
            NULL, NULL,
            (GClassInitFunc) rcd_transfer_pool_class_init,
            NULL, NULL,
            sizeof (RCDTransferPool),
            0,
            (GInstanceInitFunc) rcd_transfer_pool_init
        };

        type = g_type_register_static (G_TYPE_OBJECT,
                                       "RCDTransferPool",
                                       &type_info,
                                       0);
    }

    return type;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static void
rcd_transfer_pool_begin_transfer (RCDTransferPool *pool,
                                  RCDTransfer     *transfer)
{
    pool->running_transfers = g_slist_prepend (pool->running_transfers,
                                               transfer);

    rcd_transfer_begin (transfer);
}

static void
rcd_transfer_pool_queue_push_transfer (RCDTransferPool *pool,
                                       RCDTransfer     *transfer)
{
    pool->queued_transfers = g_slist_append (pool->queued_transfers,
                                             transfer);
}

static RCDTransfer *
rcd_transfer_pool_queue_pop_transfer (RCDTransferPool *pool)
{
    RCDTransfer *transfer;

    if (!pool->queued_transfers)
        return NULL;

    transfer = RCD_TRANSFER (pool->queued_transfers->data);

    pool->queued_transfers = g_slist_remove (pool->queued_transfers, transfer);

    return transfer;
}

static void
transfer_file_data_cb (RCDTransfer *transfer,
                       char        *buf,
                       gsize        size,
                       gpointer     user_data)
{
    RCDTransferPool *pool = RCD_TRANSFER_POOL (user_data);

    pool->current_size += size;

    if (pool->expected_size) {
        rc_pending_update_by_size (pool->pending,
                                   pool->current_size,
                                   pool->expected_size);
    } else {
        int num_transfers;
        double percent_complete = 0.0;
        GSList *iter;

        num_transfers = g_slist_length (pool->transfers);

        for (iter = pool->transfers; iter; iter = iter->next) {
            RCDTransfer *transfer = RCD_TRANSFER (iter->data);
            RCPending *pending;

            pending = rcd_transfer_get_pending (transfer);

            if (pending) {
                percent_complete += (1.0 / num_transfers) *
                    rc_pending_get_percent_complete (pending);
            }
        }

        /* Lame rounding fun */
        if (percent_complete > 100.0)
            percent_complete = 100.0;

        rc_pending_update (pool->pending, percent_complete);
    }
}

static gboolean
abort_transfers (gpointer user_data)
{
    RCDTransferPool *pool = RCD_TRANSFER_POOL (user_data);

    rcd_transfer_pool_abort (pool);

    return FALSE;
}

static void
emit_transfer_done (RCDTransferPool *pool)
{
    if (!pool->failing_error) {
        rc_pending_finished (pool->pending, 0);
    }
    else if (pool->failing_error == RCD_TRANSFER_ERROR_CANCELLED)
        rc_pending_abort (pool->pending, -1);
    else {
        char *msg;

        msg = g_strdup_printf ("%s (%s)",
                               rcd_transfer_error_to_string (pool->failing_error),
                               pool->failing_transfer->url);

        rc_pending_fail (pool->pending, -1, msg);
        g_free (msg);
    }

    g_signal_emit (pool, signals[TRANSFER_DONE], 0, pool->failing_error);
}    

static void
transfer_file_done_cb (RCDTransfer *transfer, gpointer user_data)
{
    RCDTransferPool *pool = RCD_TRANSFER_POOL (user_data);
    RCDTransferError err;
    int max_downloads = rcd_prefs_get_max_downloads ();

    pool->running_transfers = g_slist_remove (pool->running_transfers,
                                              transfer);

    /*
     * If an error occurred during one of the transfers and we're set to
     * cancel all the other transfers when one fails, do that now.
     *
     * The "failing_error" is set by the transfer that actually first
     * errored out; that way we don't have cascading cancellations between
     * all of the running transfers.
     */
    err = rcd_transfer_get_error (transfer);
    if (err && pool->abort_if_any) {
        if (!pool->failing_error) {
            pool->failing_error = err;
            pool->failing_transfer = transfer;
            /* Defer actually aborting until idle */
            g_idle_add (abort_transfers, pool);
        }
    }

    if (!pool->running_transfers &&
        (pool->failing_error || !pool->queued_transfers)) {
        /* We're done! */

        emit_transfer_done (pool);
    }

    if (pool->queued_transfers && !pool->failing_error) {
        if (g_slist_length (pool->running_transfers) < max_downloads) {
            RCDTransfer *new_transfer =
                rcd_transfer_pool_queue_pop_transfer (pool);

            rcd_transfer_pool_begin_transfer (pool, new_transfer);
        }
    }

    g_object_unref (pool);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

RCDTransferPool *
rcd_transfer_pool_new (gboolean abort_if_any, const char *description)
{
    RCDTransferPool *pool;

    pool = g_object_new (RCD_TYPE_TRANSFER_POOL, NULL);

    pool->abort_if_any = abort_if_any;

    rc_pending_set_description (pool->pending,
                                 description ? description : "Transfer pool");

    return pool;
}

void
rcd_transfer_pool_add_transfer (RCDTransferPool *pool,
                                RCDTransfer     *transfer)
{
    g_return_if_fail (RCD_IS_TRANSFER_POOL (pool));
    g_return_if_fail (RCD_IS_TRANSFER (transfer));

    if (pool->running_transfers || pool->queued_transfers) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Adding transfers to a running pool is dangerous");
    }

    pool->transfers = g_slist_append (pool->transfers,
                                      g_object_ref (transfer));

    /*
     * Because the pool could finish (and be finalized) before a transfer
     * is done, grab a ref and release it in transfer_file_done_cb()
     */
    g_object_ref (pool);

    g_signal_connect (transfer,
                      "file_data",
                      G_CALLBACK (transfer_file_data_cb),
                      pool);

    g_signal_connect (transfer,
                      "file_done",
                      G_CALLBACK (transfer_file_done_cb),
                      pool);
}

int
rcd_transfer_pool_begin (RCDTransferPool *pool)
{
    int max_downloads;
    int i;
    GSList *iter;

    g_return_val_if_fail (RCD_IS_TRANSFER_POOL (pool), -1);

    max_downloads = rcd_prefs_get_max_downloads ();

    rc_pending_begin (pool->pending);

    /*
     * Add a ref so that people can safely unref it after beginning if
     * they don't care about it afterward.
     */
    g_object_ref (pool);

    if (pool->transfers != NULL) {
        /*
         * Iterate over the list of transfers and kick them off up to
         * max_downloads, queuing the rest of later
         */
        for (iter = pool->transfers, i = 0; iter; iter = iter->next, i++) {
            RCDTransfer *t = RCD_TRANSFER (iter->data);

            if (i < max_downloads)
                rcd_transfer_pool_begin_transfer (pool, t);
            else
                rcd_transfer_pool_queue_push_transfer (pool, t);
        }
    } else {
        emit_transfer_done (pool);
    }

    return rc_pending_get_id (pool->pending);
}

void
rcd_transfer_pool_abort (RCDTransferPool *pool)
{
    g_return_if_fail (RCD_IS_TRANSFER_POOL (pool));

    if (pool->running_transfers) {
        GSList *copy, *iter;

        copy = g_slist_copy (pool->running_transfers);
        g_slist_foreach (copy, (GFunc) g_object_ref, NULL);

        for (iter = copy; iter; iter = iter->next) {
            RCDTransfer *transfer = RCD_TRANSFER (iter->data);
            RCPending *pending = rcd_transfer_get_pending (transfer);
            RCPendingStatus status = rc_pending_get_status (pending);

            if (status != RC_PENDING_STATUS_ABORTED &&
                status != RC_PENDING_STATUS_FAILED  &&
                status != RC_PENDING_STATUS_FINISHED)
                rcd_transfer_abort (transfer);
            g_object_unref (transfer);
        }

        g_slist_free (copy);
    }
}

RCPending *
rcd_transfer_pool_get_pending (RCDTransferPool *pool)
{
    g_return_val_if_fail (RCD_IS_TRANSFER_POOL (pool), NULL);

    return pool->pending;
}

void
rcd_transfer_pool_set_expected_size (RCDTransferPool *pool, gsize size)
{
    g_return_if_fail (RCD_IS_TRANSFER_POOL (pool));

    pool->expected_size = size;
}
