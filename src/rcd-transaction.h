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

typedef enum {
    RCD_TRANSACTION_FLAGS_NONE          = 0,
    RCD_TRANSACTION_FLAGS_DRY_RUN       = 1,
    RCD_TRANSACTION_FLAGS_DOWNLOAD_ONLY = 2
} RCDTransactionFlags;

void rcd_transaction_begin (const char          *name,
                            RCWorld             *world,
                            RCPackageSList      *install_packages,
                            RCPackageSList      *remove_packages,
                            RCDTransactionFlags  flags,
                            const char          *client_id,
                            const char          *client_version,
                            const char          *client_host,
                            RCDIdentity         *client_identity,
                            int                 *download_pending_id,
                            int                 *transaction_pending_id,
                            int                 *transaction_step_pending_id);

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

/*
 * rcd_transaction_log_to_server() should only be used by modules like
 * autopull, which may need to log something like a dependency failure
 * to the server before rcd_transaction_begin() can ever be called.
 *
 * Most of the time this is handled internally by rcd_transaction_begin().
 */

void rcd_transaction_log_to_server (const char         *name,
                                    RCPackageSList     *install_packages,
                                    RCPackageSList     *remove_packages,
                                    RCDTransactionFlags flags,
                                    const char         *client_id,
                                    const char         *client_version,
                                    gboolean            successful,
                                    const char         *message);

#endif /* __RCD_TRANSACTION_H__ */
