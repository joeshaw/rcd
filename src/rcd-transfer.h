/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-transfer.h
 *
 * Copyright (C) 2002 Ximian, Inc.
 *
 * Developed by Jon Trowbridge <trow@ximian.com>
 */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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
    RCD_TRANSFER_FLAGS_BLOCK          = 1 << 0,
    RCD_TRANSFER_FLAGS_DONT_CACHE     = 1 << 1,
    RCD_TRANSFER_FLAGS_FORCE_CACHE    = 1 << 2,
    RCD_TRANSFER_FLAGS_FLUSH_MEMORY   = 1 << 3,
    RCD_TRANSFER_FLAGS_RESUME_PARTIAL = 1 << 4,
    RCD_TRANSFER_FLAGS_NO_PENDING     = 1 << 5
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

struct _RCDTransfer {
    GObject parent;

    RCDTransferFlags flags;
    RCDTransferError error;
    char *error_string;

    /* Byte array of the data if we're blocking */
    GByteArray *data;

    /* URL of the file */
    char *url;

    /* Local filename */
    char *filename;

    /* Total file size */
    int file_size;

    /* Size downloaded so far */
    int trans_size;

    gboolean partial;

    /* Protocol-specific data */
    gpointer proto_data;

    /* Can this protocol-type be cached? */
    gboolean cacheable;

    /* The cache for this transfer */
    RCDCache *cache;

    /* The associated "pending" object */
    RCDPending *pending;

    gboolean cached;
    gboolean aborted;
    gboolean paused;
    int offset;

    GTimer *timer;
    GMainLoop *blocking_loop;

    /* Hack for HTTP: Content-Range overrides Content-Length in determining
       file size. */
    gboolean content_range_set;
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

GType rcd_transfer_get_type (void);

RCDTransfer *rcd_transfer_new (RCDTransferFlags  flags,
                               RCDCache         *cache);

void rcd_transfer_set_flags(RCDTransfer *t, RCDTransferFlags flags);

gint rcd_transfer_begin(RCDTransfer *t, const char *url);
GByteArray *rcd_transfer_begin_blocking (RCDTransfer *t, const char *url);

void rcd_transfer_abort(RCDTransfer *t);
void rcd_transfer_pause(RCDTransfer *t);
void rcd_transfer_resume(RCDTransfer *t);
void rcd_transfer_set_proxy_url(RCDTransfer *t, const char *url);
RCDPending *rcd_transfer_get_pending(RCDTransfer *t);
GSList *rcd_transfer_get_current_transfers(void);
RCDTransferError rcd_transfer_get_error(RCDTransfer *t);
const char *rcd_transfer_get_error_string(RCDTransfer *t);

void rc_dump_transfer_info(SoupMessage *message);


#endif /* __RCD_TRANSFER_H__ */

