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
#include "rcd-prefs.h"
#include "rcd-transfer-file.h"
#include "rcd-transfer-http.h"

#define RCD_SOUP_PROTOCOL_FILE (g_quark_from_static_string ("file"))

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

    if (t->data)
        g_byte_array_free (t->data, TRUE);

    if (parent_class->finalize)
        parent_class->finalize (obj);
}

static void
rcd_transfer_file_data (RCDTransfer *t,
                        const char  *buf,
                        gsize        size)
{
    if (t->pending && t->file_size) {
        rc_pending_update_by_size (t->pending,
                                   t->bytes_transferred,
                                   t->file_size);
    }

    if (t->flags & RCD_TRANSFER_FLAGS_BUFFER_DATA) {
        g_assert (t->data);

        t->data = g_byte_array_append (t->data, buf, size);
    }
}

static void
rcd_transfer_file_done (RCDTransfer *t)
{
    if (t->pending) {
        if (rcd_transfer_get_error (t) == RCD_TRANSFER_ERROR_CANCELLED)
            rc_pending_abort (t->pending, 0);
        else if (rcd_transfer_get_error (t))
            rc_pending_fail (t->pending, 0, rcd_transfer_get_error_string (t));
        else
            rc_pending_finished (t->pending, 0);
    }        

    /* Removes the ref added in rcd_transfer_begin() */
    g_object_unref (t);
}

static void
rcd_transfer_class_init (RCDTransferClass *klass)
{
    GObjectClass *obj_class = (GObjectClass *) klass;

    parent_class = g_type_class_peek_parent (klass);

    obj_class->finalize = rcd_transfer_finalize;

    klass->file_data = rcd_transfer_file_data;
    klass->file_done = rcd_transfer_file_done;

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
                  RCDCacheEntry    *cache_entry)
{
    RCDTransfer *t;

    g_return_val_if_fail (url, NULL);

    t = g_object_new (RCD_TYPE_TRANSFER, NULL);

    t->flags = flags;
    t->cache_entry = cache_entry;

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

RCPending *
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

const char *
rcd_transfer_error_to_string (RCDTransferError err)
{
    char *err_str;

    switch (err) {
    case RCD_TRANSFER_ERROR_NONE:
        err_str = "(no error)";
        break;
    case RCD_TRANSFER_ERROR_CANCELLED:
        err_str = "Cancelled";
        break;
    case RCD_TRANSFER_ERROR_CANT_CONNECT:
        err_str = "Can't connect";
        break;
    case RCD_TRANSFER_ERROR_FILE_NOT_FOUND:
        err_str = "File not found";
        break;
    case RCD_TRANSFER_ERROR_IO:
        err_str = "IO error";
        break;
    case RCD_TRANSFER_ERROR_CANT_AUTHENTICATE:
        err_str = "Unable to authenticate";
        break;
    case RCD_TRANSFER_ERROR_INVALID_URI:
        err_str = "Invalid URI";
        break;
    case RCD_TRANSFER_ERROR_NETWORK_DISABLED:
        err_str = "Networking disabled";
        break;
    default:
        err_str = NULL;
        g_assert_not_reached();
        break;
    }
      
    return err_str;
}

void
rcd_transfer_set_error(RCDTransfer *t, RCDTransferError err,
                       const char *err_string)
{
    const char *e;

    t->error = err;
    g_free(t->error_string);

    e = rcd_transfer_error_to_string (t->error);

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

    if (uri->protocol == SOUP_PROTOCOL_HTTP
        || uri->protocol == SOUP_PROTOCOL_HTTPS)
        protocol = rcd_transfer_protocol_http_new ();
    else if (uri->protocol == RCD_SOUP_PROTOCOL_FILE)
        protocol = rcd_transfer_protocol_file_new ();
    else
        protocol = NULL;

    soup_uri_free (uri);

    return protocol;
} /* rcd_transfer_get_protocol_from_url */

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

    /*
     * Add a ref so that people can safely unref it after beginning
     * the transfer if they don't care about it afterward.  This ref
     * is cleaned up in rcd_transfer_file_done().  It's important that
     * we do this ref before the protocol's open_func is called, since
     * it's possible (at least with the HTTP backend) to synchonously
     * call the rcd_transfer_file_done() function from within it.  If
     * open_func returns -1, however, we'll clean up the ref.
     */
    g_object_ref (t);

    /* Create associated RCPending object */
    if (!t->pending && ! (t->flags & RCD_TRANSFER_FLAGS_NO_PENDING)) {
        char *desc;

        desc = g_strdup_printf ("Downloading %s", t->url);
        t->pending = rc_pending_new (desc);
        g_free (desc);

        rc_pending_begin (t->pending);
    }

    /* Buffer our data (if the flag is set) */
    if (t->data) {
        g_byte_array_free (t->data, TRUE);
        t->data = NULL;
    }

    if (t->flags & RCD_TRANSFER_FLAGS_BUFFER_DATA) {
        t->data = g_byte_array_new ();
    }


    if (t->protocol->open_func (t)) {
        /* An error occurred in the open call. It's the open call's
           responsibility to rcd_transfer_set_error() the appropriate
           error. */
        g_object_unref (t);
        return -1;
    }

    return t->pending ? rc_pending_get_id (t->pending) : 0;
} /* rcd_transfer_begin */

static void
blocking_file_done_cb (RCDTransfer *t, gpointer user_data)
{
    GMainLoop *main_loop = user_data;

    g_main_loop_quit (main_loop);
}

const GByteArray *
rcd_transfer_begin_blocking (RCDTransfer *t)
{
    GMainLoop *main_loop;
    RCDTransferFlags old_flags;
    gint id;

    g_return_val_if_fail (RCD_IS_TRANSFER (t), NULL);

    old_flags = t->flags;
    t->flags |= RCD_TRANSFER_FLAGS_BUFFER_DATA;

    main_loop = g_main_loop_new (NULL, TRUE);

    g_signal_connect (t, "file_done",
                      G_CALLBACK (blocking_file_done_cb), main_loop);

    id = rcd_transfer_begin (t);

    if (id != -1) {
        /* Wait until the transfer has finished */
        g_main_loop_run (main_loop);
    }

    g_signal_handlers_disconnect_by_func (
        t, G_CALLBACK (blocking_file_done_cb), main_loop);

    g_main_loop_unref (main_loop);

    t->flags = old_flags;

    return t->data;
}

