/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rc-you-transaction.h
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

#ifndef __RC_YOU_TRANSACTION__
#define __RC_YOU_TRANSACTION__

#include <rcd-transaction.h>
#include "rc-you-patch.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _RCYouTransaction RCYouTransaction;
typedef struct _RCYouTransactionClass RCYouTransactionClass;

struct _RCYouTransaction {
    GObject parent;

    char *name;

    char *id;

    RCYouPatchSList *patches;
    RCYouFileSList  *files_to_download;

    RCDTransactionFlags flags;

    RCDTransferPool *pool;

    RCPending *download_pending;
    RCPending *transaction_pending;
    RCPending *transaction_step_pending;

    gsize total_download_size;
    gsize current_download_size;

    gboolean locked;

    int total_transaction_steps;

    gsize transaction_size;

    char *client_id;
    char *client_version;
    char *client_host;
    RCDIdentity *client_identity;

    time_t start_time;
};

struct _RCYouTransactionClass {
    GObjectClass parent_class;

    void (*transaction_started) (RCYouTransaction *);
    void (*transaction_finished) (RCYouTransaction *);
};

#define RC_TYPE_YOU_TRANSACTION             (rc_you_transaction_get_type ())
#define RC_YOU_TRANSACTION(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), \
                                            RC_TYPE_YOU_TRANSACTION, \
                                            RCYouTransaction))
#define RC_YOU_TRANSACTION_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), \
                                            RC_TYPE_YOU_TRANSACTION, \
                                            RCYouTransactionClass))
#define RC_IS_YOU_TRANSACTION(obj)          (G_TYPE_CHECK_INSTANCE_TYPE  ((obj), \
                                            RC_TYPE_YOU_TRANSACTION))
#define RC_IS_YOU_TRANSACTION_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), \
                                            RC_TYPE_YOU_TRANSACTION))

GType rc_you_transaction_get_type (void);

RCYouTransaction *rc_you_transaction_new (void);

void rc_you_transaction_set_name        (RCYouTransaction *transaction,
                                         const char     *name);
void rc_you_transaction_set_patches     (RCYouTransaction *transaction,
                                         RCYouPatchSList *patches);
void rc_you_transaction_set_flags       (RCYouTransaction *transaction,
                                         RCDTransactionFlags flags);
void rc_you_transaction_set_client_info (RCYouTransaction *transaction,
                                         const char     *client_id,
                                         const char     *client_version,
                                         const char     *client_host,
                                         RCDIdentity    *client_identity);

void rc_you_transaction_set_id          (RCYouTransaction *transaction,
                                         const char *id);

RCPending *rc_you_transaction_get_download_pending    (RCYouTransaction *transaction);
RCPending *rc_you_transaction_get_transaction_pending (RCYouTransaction *transaction);
RCPending *rc_you_transaction_get_step_pending        (RCYouTransaction *transaction);


/*
 * Begins the transaction.  Causes it to ref itself, so it is safe to unref
 * it after you are done calling methods on it, even if the transaction
 * hasn't yet finished.  (Be careful not to unref it until you are done with
 * it, though)
 */
void rc_you_transaction_begin (RCYouTransaction *transaction);

int rc_you_transaction_abort (int download_id, RCDIdentity *identity);

gboolean rc_you_transaction_is_valid (int download_id);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /*__RC_YOU_TRANSACTION__ */
