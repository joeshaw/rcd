/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-transaction.h
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

#ifndef __RCD_TRANSACTION_H__
#define __RCD_TRANSACTION_H__

#include <libredcarpet.h>

#include "rcd-identity.h"
#include "rcd-transfer-pool.h"

typedef   enum _RCDTransactionFlags RCDTransactionFlags;
typedef struct _RCDTransaction      RCDTransaction;
typedef struct _RCDTransactionClass RCDTransactionClass;

enum _RCDTransactionFlags {
    RCD_TRANSACTION_FLAGS_NONE          = 0,
    RCD_TRANSACTION_FLAGS_DRY_RUN       = 1,
    RCD_TRANSACTION_FLAGS_DOWNLOAD_ONLY = 2
};

struct _RCDTransaction {
    GObject parent;

    char *name;

    char *id;

    RCWorld *world;

    RCPackageSList *install_packages;
    RCPackageSList *remove_packages;

    RCPackageSList *packages_to_download;

    GHashTable *old_packages; /* For tracking upgrades */

    RCDTransactionFlags flags;
    gboolean rollback;

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

    GPid stat_pid;
    time_t stat_start;
    
    time_t start_time;
};

struct _RCDTransactionClass {
    GObjectClass parent_class;

    void (*transaction_started) (RCDTransaction *);
    void (*transaction_finished) (RCDTransaction *);
};

#define RCD_TYPE_TRANSACTION             (rcd_transaction_get_type ())
#define RCD_TRANSACTION(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), \
                                          RCD_TYPE_TRANSACTION, \
                                          RCDTransaction))
#define RCD_TRANSACTION_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), \
                                          RCD_TYPE_TRANSACTION, \
                                          RCDTransactionClass))
#define RCD_IS_TRANSACTION(obj)          (G_TYPE_CHECK_INSTANCE_TYPE  ((obj), \
                                          RCD_TYPE_TRANSACTION))
#define RCD_IS_TRANSACTION_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), \
                                          RCD_TYPE_TRANSACTION))

GType rcd_transaction_get_type (void);

RCDTransaction *rcd_transaction_new (void);

void rcd_transaction_set_name             (RCDTransaction *transaction,
                                           const char     *name);
void rcd_transaction_set_install_packages (RCDTransaction *transaction,
                                           RCPackageSList *install_packages);
void rcd_transaction_set_remove_packages  (RCDTransaction *transaction,
                                           RCPackageSList *remove_packages);
void rcd_transaction_set_flags            (RCDTransaction *transaction,
                                           RCDTransactionFlags flags);
void rcd_transaction_set_rollback         (RCDTransaction *transaction,
                                           gboolean rollback);
void rcd_transaction_set_client_info      (RCDTransaction *transaction,
                                           const char     *client_id,
                                           const char     *client_version,
                                           const char     *client_host,
                                           RCDIdentity    *client_identity);

void rcd_transaction_set_id               (RCDTransaction *transaction,
                                           const char *id);

RCPending *rcd_transaction_get_download_pending    (RCDTransaction *transaction);
RCPending *rcd_transaction_get_transaction_pending (RCDTransaction *transaction);
RCPending *rcd_transaction_get_step_pending        (RCDTransaction *transaction);

/*
 * Begins the transaction.  Causes it to ref itself, so it is safe to unref
 * it after you are done calling methods on it, even if the transaction
 * hasn't yet finished.  (Be careful not to unref it until you are done with
 * it, though)
 */
void rcd_transaction_begin (RCDTransaction *transaction);

int rcd_transaction_abort (int download_id, RCDIdentity *identity);

gboolean rcd_transaction_is_valid (int download_id);

/*
 * Global transaction locks.  rcd_transaction_begin() will lock and
 * unlock as necessary, so make sure to check if it is locked before
 * trying to lock or unlock it.
 */

void     rcd_transaction_lock      (void);
void     rcd_transaction_unlock    (void);
gboolean rcd_transaction_is_locked (void);

/* Check the size and md5 integrity of a package. */
gboolean rcd_transaction_check_package_integrity (const char *filename);



#endif /* __RCD_TRANSACTION_H__ */
