/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-transfer.h
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

#ifndef __RCD_TRANSFER_H__
#define __RCD_TRANSFER_H__

#include <glib-object.h>
#include <libsoup/soup.h>

#include "rcd-cache.h"
#include "rcd-pending.h"

typedef   enum _RCDTransferFlags RCDTransferFlags;
typedef   enum _RCDTransferError RCDTransferError;
typedef struct _RCDTransfer      RCDTransfer;
typedef struct _RCDTransferClass RCDTransferClass;

enum _RCDTransferFlags {
    RCD_TRANSFER_FLAGS_NONE           = 0,
    RCD_TRANSFER_FLAGS_DONT_CACHE     = 1 << 1,
    RCD_TRANSFER_FLAGS_FORCE_CACHE    = 1 << 2,
    RCD_TRANSFER_FLAGS_RESUME_PARTIAL = 1 << 3,
    RCD_TRANSFER_FLAGS_NO_PENDING     = 1 << 4
};

enum _RCDTransferError {
    RCD_TRANSFER_ERROR_NONE = 0,
    RCD_TRANSFER_ERROR_CANCELLED,
    RCD_TRANSFER_ERROR_CANT_CONNECT,
    RCD_TRANSFER_ERROR_FILE_NOT_FOUND,
    RCD_TRANSFER_ERROR_IO,
    RCD_TRANSFER_ERROR_CANT_AUTHENTICATE,
    RCD_TRANSFER_ERROR_INVALID_URI
};

typedef struct _RCDTransferProtocol RCDTransferProtocol;

struct _RCDTransferProtocol {
    const char *name;

    char *(*get_local_filename_func) (RCDTransfer *t);
    int   (*open_func)               (RCDTransfer *t);
    void  (*abort_func)              (RCDTransfer *t);

    void  (*free_func)               (RCDTransferProtocol *t);
};

struct _RCDTransfer {
    GObject parent;

    RCDTransferFlags flags;

    RCDTransferError error;
    char *error_string;

    char *url;
    char *filename;

    RCDCache *cache;

    RCDPending *pending;

    RCDTransferProtocol *protocol;

    gsize file_size;
    gsize bytes_transferred;
};

struct _RCDTransferClass {
    GObjectClass parent_class;
    
    void (*file_data) (RCDTransfer *, char *buffer, gsize size);
    void (*file_done) (RCDTransfer *);
};

#define RCD_TYPE_TRANSFER            (rcd_transfer_get_type ())
#define RCD_TRANSFER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), \
                                     RCD_TYPE_TRANSFER, RCDTransfer))
#define RCD_TRANSFER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), \
                                     RCD_TYPE_TRANSFER, RCDTransferClass))
#define RCD_IS_TRANSFER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), \
                                     RCD_TYPE_TRANSFER))
#define RCD_IS_TRANSFER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), \
                                     RCD_TYPE_TRANSFER))

GType             rcd_transfer_get_type           (void);

RCDTransfer      *rcd_transfer_new                (const char       *url,
                                                   RCDTransferFlags  flags,
                                                   RCDCache         *cache);

void              rcd_transfer_set_flags          (RCDTransfer *t,
                                                   RCDTransferFlags flags);

int               rcd_transfer_begin              (RCDTransfer *t);
GByteArray       *rcd_transfer_begin_blocking     (RCDTransfer *t);
void              rcd_transfer_abort              (RCDTransfer *t);

void              rcd_transfer_emit_data          (RCDTransfer *t,
                                                   const char  *buf,
                                                   gsize       size);
void              rcd_transfer_emit_done          (RCDTransfer *t);

RCDPending       *rcd_transfer_get_pending        (RCDTransfer *t);
char             *rcd_transfer_get_local_filename (RCDTransfer *t);

RCDTransferError  rcd_transfer_get_error          (RCDTransfer *t);
const char       *rcd_transfer_get_error_string   (RCDTransfer *t);

void              rcd_transfer_set_error          (RCDTransfer *t,
                                                   RCDTransferError err,
                                                   const char *err_string);

RCDTransferProtocol *rcd_transfer_get_protocol_from_url (const char *url);


#endif /* __RCD_TRANSFER_H__ */

