/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-transfer-pool.h
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

#ifndef __RCD_TRANSFER_POOL_H__
#define __RCD_TRANSFER_POOL_H__

#include <glib-object.h>

#include "rcd-transfer.h"

typedef struct _RCDTransferPool      RCDTransferPool;
typedef struct _RCDTransferPoolClass RCDTransferPoolClass;

struct _RCDTransferPool {
    GObject parent;

    gboolean abort_if_any;
    GSList *transfers;
    RCPending *pending;
    gsize expected_size;

    /* Running state */
    RCDTransferError failing_error;
    RCDTransfer *failing_transfer;
    gsize current_size;
    GSList *running_transfers;
    GSList *queued_transfers;
};

struct _RCDTransferPoolClass {
    GObjectClass parent_class;
    
    void (*transfer_done) (RCDTransferPool *, RCDTransferError error);
};

#define RCD_TYPE_TRANSFER_POOL            (rcd_transfer_pool_get_type ())
#define RCD_TRANSFER_POOL(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), \
                                           RCD_TYPE_TRANSFER_POOL, \
                                           RCDTransferPool))
#define RCD_TRANSFER_POOL_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), \
                                           RCD_TYPE_TRANSFER_POOL, \
                                           RCDTransferPoolClass))
#define RCD_IS_TRANSFER_POOL(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), \
                                           RCD_TYPE_TRANSFER_POOL))
#define RCD_IS_TRANSFER_POOL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), \
                                           RCD_TYPE_TRANSFER_POOL))

GType             rcd_transfer_pool_get_type      (void);

RCDTransferPool  *rcd_transfer_pool_new           (gboolean abort_if_any,
                                                   const char *description);

void              rcd_transfer_pool_add_transfer  (RCDTransferPool *pool,
                                                   RCDTransfer     *transfer);

/* Returns RCPending ID */
int               rcd_transfer_pool_begin         (RCDTransferPool *pool);

void              rcd_transfer_pool_abort         (RCDTransferPool *pool);

RCPending        *rcd_transfer_pool_get_pending   (RCDTransferPool *pool);

void              rcd_transfer_pool_set_expected_size (RCDTransferPool *pool,
                                                       gsize size);

#endif /* __RCD_TRANSFER_POOL_H__ */

