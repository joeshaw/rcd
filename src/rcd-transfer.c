/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-transfer.c
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
#include "rcd-transfer.h"

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <libsoup/soup.h>
#include <libredcarpet.h>

#include "rcd-cache.h"
#include "rcd-marshal.h"
#include "rcd-pending.h"
#include "rcd-prefs.h"
#include "rcd-transfer-file.h"
#include "rcd-transfer-http.h"

#define _(x) x

static GObjectClass *parent_class;

enum {
    FILE_DATA,
    FILE_DONE,
    LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void
rcd_transfer_finalize (GObject *obj)
{
    RCDTransfer *t = RCD_TRANSFER (obj);

    g_free (t->filename);
    g_free (t->url);
    g_free (t->error_string);

    if (t->protocol) {
        if (t->protocol->free_func)
            t->protocol->free_func (t->protocol);
        else
            g_free (t->protocol);
    }

    if (t->pending)
        g_object_unref (t->pending);

    if (parent_class->finalize)
        parent_class->finalize (obj);
}

static void
rcd_transfer_class_init (RCDTransferClass *klass)
{
    GObjectClass *obj_class = (GObjectClass *) klass;

    parent_class = g_type_class_peek_parent (klass);

    obj_class->finalize = rcd_transfer_finalize;

    signals[FILE_DATA] =
        g_signal_new ("file_data",
                      G_TYPE_FROM_CLASS (klass),
                      G_SIGNAL_RUN_FIRST,
                      G_STRUCT_OFFSET (RCDTransferClass, file_data),
                      NULL, NULL,
                      rcd_marshal_VOID__POINTER_UINT,
                      G_TYPE_NONE, 2,
                      G_TYPE_POINTER, G_TYPE_UINT);

    signals[FILE_DONE] =
        g_signal_new ("file_done",
                      G_TYPE_FROM_CLASS (klass),
                      G_SIGNAL_RUN_FIRST,
                      G_STRUCT_OFFSET (RCDTransferClass, file_done),
                      NULL, NULL,
                      rcd_marshal_VOID__VOID,
                      G_TYPE_NONE, 0);
}

static void
rcd_transfer_init (RCDTransfer *t)
{
    /* FIXME: Need to support proxies */

    t->error = RCD_TRANSFER_ERROR_NONE;
}

GType
rcd_transfer_get_type (void)
{
    static GType type = 0;

    if (! type) {
        static GTypeInfo type_info = {
            sizeof (RCDTransferClass),
            NULL, NULL,
            (GClassInitFunc) rcd_transfer_class_init,
            NULL, NULL,
            sizeof (RCDTransfer),
            0,
            (GInstanceInitFunc) rcd_transfer_init
        };

        type = g_type_register_static (G_TYPE_OBJECT,
                                       "RCDTransfer",
                                       &type_info,
                                       0);
    }

    return type;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

RCDTransfer *
rcd_transfer_new (const char       *url,
                  RCDTransferFlags  flags,
                  RCDCache         *cache)
{
    RCDTransfer *t;

    g_return_val_if_fail (url, NULL);

    t = g_object_new (RCD_TYPE_TRANSFER, NULL);

    t->flags = flags;
    t->cache = cache;

    t->protocol = rcd_transfer_get_protocol_from_url (url);

    if (!t->protocol)
        rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_INVALID_URI, url);
        
    t->url = g_strdup (url);
    t->filename = g_path_get_basename (t->url);

    return t;
}

void
rcd_transfer_set_flags(RCDTransfer *t, RCDTransferFlags flags)
{
    g_return_if_fail(RCD_IS_TRANSFER(t));

    t->flags = flags;
} /* rcd_transfer_set_flags */

RCDPending *
rcd_transfer_get_pending (RCDTransfer *t)
{
    g_return_val_if_fail (RCD_IS_TRANSFER (t), NULL);

    return t->pending;
}

char *
rcd_transfer_get_local_filename (RCDTransfer *t)
{
    g_return_val_if_fail (RCD_IS_TRANSFER (t), NULL);

    return t->protocol->get_local_filename_func (t);
} /* rcd_transfer_get_local_filename */

RCDTransferError
rcd_transfer_get_error(RCDTransfer *t)
{
    g_return_val_if_fail (RCD_IS_TRANSFER (t), RCD_TRANSFER_ERROR_NONE);

    return t->error;
} /* rcd_transfer_get_error */

const char *
rcd_transfer_get_error_string(RCDTransfer *t)
{
    g_return_val_if_fail(RCD_IS_TRANSFER (t), NULL);
    g_return_val_if_fail(t->error, NULL);

    return t->error_string;
} /* rcd_transfer_get_error_string */

static const char *
error_to_string(RCDTransfer *t)
{
    char *err;

    switch (t->error) {
    case RCD_TRANSFER_ERROR_NONE:
        err = "(no error)";
        break;
    case RCD_TRANSFER_ERROR_CANCELLED:
        err = "Cancelled";
        break;
    case RCD_TRANSFER_ERROR_CANT_CONNECT:
        err = "Can't connect";
        break;
    case RCD_TRANSFER_ERROR_FILE_NOT_FOUND:
        err = "File not found";
        break;
    case RCD_TRANSFER_ERROR_IO:
        err = "IO error";
        break;
    case RCD_TRANSFER_ERROR_CANT_AUTHENTICATE:
        err = "Unable to authenticate";
        break;
    case RCD_TRANSFER_ERROR_INVALID_URI:
        err = "Invalid URI";
        break;
    default:
        err = NULL;
        g_assert_not_reached();
        break;
    }
      
    return err;
} /* error_to_string */

void
rcd_transfer_set_error(RCDTransfer *t, RCDTransferError err,
                       const char *err_string)
{
    const char *e;

    t->error = err;
    g_free(t->error_string);

    e = error_to_string(t);

    if (err_string)
        t->error_string = g_strdup_printf("%s - %s", e, err_string);
    else
        t->error_string = g_strdup(e);
} /* rcd_transfer_set_error */

void
rcd_transfer_emit_data (RCDTransfer *t, const char *buf, gsize size)
{
    t->bytes_transferred += size;

    g_signal_emit (t, signals[FILE_DATA], 0, buf, size);
} /* rcd_transfer_emit_data */

void
rcd_transfer_emit_done (RCDTransfer *t)
{
    g_signal_emit(t, signals[FILE_DONE], 0);
} /* rcd_transfer_emit_done */

void
rcd_transfer_abort (RCDTransfer *t)
{
    g_return_if_fail (RCD_IS_TRANSFER (t));

    t->protocol->abort_func (t);
} /* rcd_transfer_abort */

RCDTransferProtocol *
rcd_transfer_get_protocol_from_url (const char *url)
{
    SoupUri *uri = soup_uri_new (url);
    RCDTransferProtocol *protocol;

    if (!uri)
        return NULL;

    switch (uri->protocol) {
    case SOUP_PROTOCOL_HTTP:
    case SOUP_PROTOCOL_HTTPS:
        protocol = rcd_transfer_protocol_http_new ();
        break;
    case SOUP_PROTOCOL_FILE:
        protocol = rcd_transfer_protocol_file_new ();
        break;
    default:
        protocol = NULL;
        break;
    }

    soup_uri_free (uri);

    return protocol;
} /* rcd_transfer_get_protocol_from_url */

static void
pending_file_data_cb (RCDTransfer *t,
                      char        *buf,
                      gsize        size,
                      gpointer     user_data)
{
    RCDPending *pending = user_data;

    if (t->file_size) {
        rcd_pending_update_by_size (pending, t->bytes_transferred,
                                    t->file_size);
    }
} /* pending_file_data_cb */

static void
pending_file_done_cb (RCDTransfer *t, gpointer user_data)
{
    RCDPending *pending = user_data;

    if (rcd_transfer_get_error (t) == RCD_TRANSFER_ERROR_CANCELLED)
        rcd_pending_abort (pending, 0);
    else if (rcd_transfer_get_error (t))
        rcd_pending_fail (pending, 0, rcd_transfer_get_error_string (t));
    else
        rcd_pending_finished (pending, 0);
} /* pending_file_done_cb */

int
rcd_transfer_begin (RCDTransfer *t)
{
    g_return_val_if_fail (RCD_IS_TRANSFER (t), -1);

    t->bytes_transferred = 0;

    if (!t->protocol) {
        rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_INVALID_URI, t->url);
        return -1;
    }

    rc_debug(RC_DEBUG_LEVEL_DEBUG, "Transfer URL: %s\n", t->url);

    if (t->protocol->open_func (t)) {
        /* An error occurred in the open call. It's the open call's
           responsibility to rcd_transfer_set_error() the appropriate
           error. */
        return -1;
    }

    /* Create associated RCPending object */
    if (!t->pending && ! (t->flags & RCD_TRANSFER_FLAGS_NO_PENDING)) {
        char *desc;

        desc = g_strdup_printf ("Downloading %s", t->url);
        t->pending = rcd_pending_new (desc);
        g_free (desc);

        g_signal_connect (t,
                          "file_data",
                          (GCallback) pending_file_data_cb,
                          t->pending);

        g_signal_connect (t,
                          "file_done",
                          (GCallback) pending_file_done_cb,
                          t->pending);

        rcd_pending_begin (t->pending);
    }

    return t->pending ? rcd_pending_get_id (t->pending) : 0;
} /* rcd_transfer_begin */

typedef struct {
    GMainLoop  *main_loop;
    GByteArray *data;
} BlockingTransferClosure;

static void
blocking_file_data_cb (RCDTransfer *t,
                       const char  *buf,
                       gsize        size,
                       gpointer     user_data)
{
    BlockingTransferClosure *closure = user_data;

    closure->data = g_byte_array_append (closure->data, buf, size);
} /* blocking_file_data_cb */

static void
blocking_file_done_cb (RCDTransfer *t, gpointer user_data)
{
    BlockingTransferClosure *closure = user_data;

    g_main_loop_quit (closure->main_loop);
}

GByteArray *
rcd_transfer_begin_blocking (RCDTransfer *t)
{
    BlockingTransferClosure closure;
    gint id;

    g_return_val_if_fail (RCD_IS_TRANSFER (t), NULL);

    closure.data = g_byte_array_new ();
    closure.main_loop = g_main_loop_new (NULL, TRUE);

    g_signal_connect (t, "file_data",
                      G_CALLBACK (blocking_file_data_cb), &closure);
    g_signal_connect (t, "file_done",
                      G_CALLBACK (blocking_file_done_cb), &closure);

    id = rcd_transfer_begin (t);

    /* Wait until the transfer has finished */
    g_main_loop_run (closure.main_loop);

    g_main_loop_unref (closure.main_loop);

    g_signal_handlers_disconnect_by_func (
        t, G_CALLBACK (blocking_file_data_cb), &closure);
    g_signal_handlers_disconnect_by_func (
        t, G_CALLBACK (blocking_file_done_cb), &closure);

    /* FIXME: do something smart w/ the id here. */

    return closure.data;
}

