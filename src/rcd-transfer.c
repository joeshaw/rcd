/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-transfer.c
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

#include <config.h>
#include "rcd-transfer.h"

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <libsoup/soup.h>
#include <libredcarpet.h>
#include "rcd-prefs.h"
#include "rcd-cache.h"
#include "rcd-pending.h"
#include "rcd-marshal.h"

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
    if (t->timer)
        g_timer_destroy (t->timer);
    g_free (t->error_string);

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
                      rcd_marshal_VOID__STRING_INT,
                      G_TYPE_NONE, 2,
                      G_TYPE_STRING, G_TYPE_INT);

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
    t->cache = NULL;
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

#define BLOCK_SIZE 8192

#define HTTP_RESPONSE_SUCCESSFUL(x)   ((x) >= 200 && (x) < 300)
#define HTTP_RESPONSE_REDIRECT(x)     ((x) >= 300 && (x) < 400)
#define HTTP_RESPONSE_CLIENT_ERROR(x) ((x) >= 400 && (x) < 400)
#define HTTP_RESPONSE_SERVER_ERROR(x) ((x) >= 500 && (x) < 600)

#define HTTP_RESPONSE_AUTH_FAILURE(x) ((x) == 401 || (x) == 407)
#define HTTP_RESPONSE_NOT_MODIFIED(x) ((x) == 304)

/* GSList of RCDTransfers */
static GSList *current_transfers = NULL;

RCDTransfer *
rcd_transfer_new (RCDTransferFlags flags,
                  RCDCache *cache)
{
    RCDTransfer *t;

    t = g_object_new (RCD_TYPE_TRANSFER, NULL);

    t->flags = flags;
    t->cache = cache;

    return t;
}

void
rcd_transfer_set_flags(RCDTransfer *t, RCDTransferFlags flags)
{
    g_return_if_fail(RCD_IS_TRANSFER(t));

    t->flags = flags;
} /* rcd_transfer_set_flags */

void
rcd_transfer_set_proxy_url(RCDTransfer *t, const char *url)
{
    SoupContext *context;

    g_return_if_fail (RCD_IS_TRANSFER (t));

    if (url && *url) {
        context = soup_context_get(url);
        soup_set_proxy(context);
    }
    else
        soup_set_proxy(NULL);
} /* rcd_transfer_set_proxy_info */

RCDPending *
rcd_transfer_get_pending (RCDTransfer *t)
{
    g_return_val_if_fail (RCD_IS_TRANSFER (t), NULL);

    return t->pending;
}

GSList *
rcd_transfer_get_current_transfers(void)
{
    return current_transfers;
} /* rcd_transfer_get_current_transfers */

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

static void
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

static void
rcd_transfer_emit_data(RCDTransfer *t, char *buf, guint64 size)
{
    t->trans_size += size;

    if (!(t->flags & RCD_TRANSFER_FLAGS_FLUSH_MEMORY)) {
        if (!t->data)
            t->data = g_byte_array_new();
        
        t->data = g_byte_array_append(t->data, buf, size);
    }

    g_signal_emit(t, signals[FILE_DATA], 0, buf, size);
} /* rcd_transfer_emit_data */

static void
rcd_transfer_emit_done(RCDTransfer *t)
{
    current_transfers = g_slist_remove(current_transfers, t);

    if (!rcd_transfer_get_error(t)) {
        if (t->timer)
            g_timer_stop(t->timer);
    }
    g_signal_emit(t, signals[FILE_DONE], 0);

    if (t->flags & RCD_TRANSFER_FLAGS_BLOCK) {
        g_main_loop_quit (t->blocking_loop);
        t->blocking_loop = NULL;
    }
    else {
        /* If this transfer is non-blocking, we want to free up the memory
           in the buffer. */
        if (t->data)
            g_byte_array_free(t->data, TRUE);
        t->data = NULL;
    }
} /* rcd_transfer_emit_done */

static void
rcd_transfer_file_info(RCDTransfer *t)
{
    if (!t->timer)
        t->timer = g_timer_new();
    else
        g_timer_reset(t->timer);

    g_timer_start(t->timer);
} /* rcd_transfer_file_info */

#if 0
static int
parse_month(char *month)
{
    char *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug",
                       "Sep", "Oct", "Nov", "Dec" };
    int i;

    for (i = 0; i < 12; i++) {
        if (g_strncasecmp(month, months[i], 3) == 0)
            return i;
    }

    g_assert_not_reached();
    return 0;
} /* parse_month */

static time_t
parse_http_time(const char *header)
{
    struct tm *tm;
    time_t tt;
    char **split;
    char **time;
    char **date;

    g_return_val_if_fail(header, -1);

    /* According to RFC 2616, all HTTP 1.1 compliant clients must be able to
       parse dates in any one of the following three formats:

       Sun, 06 Nov 1994 08:49:37 GMT  ; RFC 822, updated by RFC 1123
       Sunday, 06-Nov-94 08:49:37 GMT ; RFC 850, obsoleted by RFC 1036 
       Sun Nov  6 08:49:37 1994       ; ANSI C's asctime() format

       The key, as you can see, is the 4th character, which will tell us
       which format we are in. */

    tm = g_new0(struct tm, 1);

    if (header[3] == ',') {
        /* Sun, 06 Nov 1994 08:49:37 GMT */

        split = g_strsplit(header, " ", 0);
        tm->tm_mday = atoi(split[1]);
        tm->tm_mon = parse_month(split[2]);
        tm->tm_year = atoi(split[3]) - 1900;
        time = g_strsplit(split[4], ":", 0);
        tm->tm_hour = atoi(time[0]);
        tm->tm_min = atoi(time[1]);
        tm->tm_sec = atoi(time[2]);
        g_strfreev(time);
        g_strfreev(split);
    }
    else if (header[3] == ' ') {
        /* Sun Nov  6 08:49:37 1994 */
        int i;

        split = g_strsplit(header, " ", 0);
        tm->tm_mon = parse_month(split[1]);
        i = 2;
        if (!split[i][0])
            i++;
        tm->tm_mday = atoi(split[i++]);
        time = g_strsplit(split[i++], ":", 0);
        tm->tm_hour = atoi(time[0]);
        tm->tm_min = atoi(time[1]);
        tm->tm_sec = atoi(time[2]);
        g_strfreev(time);
        tm->tm_year = atoi(split[i]);
        g_strfreev(split);
    }
    else {
        /* Sunday, 06-Nov-94 08:49:37 GMT */
        int y;

        split = g_strsplit(header, " ", 0);
        date = g_strsplit(split[1], "-", 0);
        tm->tm_mday = atoi(date[0]);
        tm->tm_mon = parse_month(date[1]);
        /* Two digit dates. Wonderful. Lets assume that anything before the 
           epoch is a 21st century date and afterward is 20th. */
        y = atoi(date[2]);
        if (y >= 70)
            tm->tm_year = y;
        else
            tm->tm_year = 100 + y;
        g_strfreev(date);
        time = g_strsplit(split[2], ":", 0);
        tm->tm_hour = atoi(time[0]);
        tm->tm_min = atoi(time[1]);
        tm->tm_sec = atoi(time[2]);
        g_strfreev(time);
        g_strfreev(split);
    }

    tm->tm_isdst = -1;
        
    tt = mktime(tm);
    g_free(tm);
    
    return tt;
} /* parse_http_time */
#endif

/* Check the following conditions:
 *    (1) That this transfer type is cacheable.  http is, but file isn't.
 *    (2) That this transfer is set to flush memory after each chunk.  If it
 *        is, we have to put the data *somewhere*, so it goes to disk even
 *        if caching is turned off.
 *    (3) That caching is enabled.
 */
static gboolean
is_cacheable(RCDTransfer *t)
{
    if (!t->cacheable)
        return FALSE;

    if (t->flags & RCD_TRANSFER_FLAGS_FLUSH_MEMORY)
        return TRUE;

    if (rcd_prefs_get_cache_enabled() ||
        t->flags & RCD_TRANSFER_FLAGS_FORCE_CACHE)
        return TRUE;
    else
        return FALSE;
} /* is_cacheable */

static gboolean
file_read_data(GIOChannel *iochannel,
               GIOCondition condition,
               gpointer data)
{
    RCDTransfer *transfer = data;
    GIOError err;
    char buf[BLOCK_SIZE];
    gsize bytes;
    int watch;

    watch = GPOINTER_TO_INT(transfer->proto_data);

    if (!(condition & G_IO_IN))
        goto ERROR;

    err = g_io_channel_read(iochannel, buf, BLOCK_SIZE, &bytes);

    if (bytes)
        rcd_transfer_emit_data(transfer, buf, bytes);

    /* G_IO_ERROR_AGAIN means that there is more data to read off the channel */
    if (err == G_IO_ERROR_AGAIN)
        return TRUE;

    if (err != G_IO_ERROR_NONE)
        goto ERROR;

    if (bytes > 0) {
        /* More data to read. Whee. */
        return TRUE;
    }
    else {
        /* No more bytes to read and no error condition; the file is done */
        g_io_channel_close(iochannel);
        rcd_transfer_emit_done(transfer);

        return FALSE;
    }

ERROR:
    g_source_remove(watch);

    rcd_transfer_set_error(transfer, RCD_TRANSFER_ERROR_IO, NULL);
    rcd_transfer_emit_done(transfer);

    return FALSE;
} /* file_read_data */

static void
file_pause(RCDTransfer *t)
{
    int watch = GPOINTER_TO_INT(t->proto_data);

#if 0
    /* FIXME */
    rc_debug(RC_DEBUG_LEVEL_DEBUG, "PAUSE! Trans size: %d\n", t->trans_size);
#endif

    g_source_remove(watch);

    t->offset = t->trans_size + t->offset;
    t->trans_size = 0;
} /* file_pause */

static void
file_abort(RCDTransfer *t)
{
    int watch = GPOINTER_TO_INT(t->proto_data);

    g_source_remove(watch);

    rcd_transfer_set_error(t, RCD_TRANSFER_ERROR_CANCELLED, NULL);
    rcd_transfer_emit_done(t);
} /* file_abort */
        
static int
file_open(RCDTransfer *t, int offset)
{
    /* Discard the "file://" portion of the URL */
    const char *filename = t->url + 7;
    int fd;
    struct stat fdstat;
    GIOChannel *iochannel;
    int watch;

    if (stat(filename, &fdstat)) {
        rcd_transfer_set_error(t, RCD_TRANSFER_ERROR_FILE_NOT_FOUND, NULL);
        return -1;
    }

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        rcd_transfer_set_error(
            t, RCD_TRANSFER_ERROR_IO, _("Couldn't open file for writing"));
        return -1;
    }

    t->file_size = fdstat.st_size;

    rcd_transfer_file_info(t);

    iochannel = g_io_channel_unix_new(fd);

    if (t->offset) {
        GIOError err;

        err = g_io_channel_seek(iochannel, t->offset, G_SEEK_SET);

        if (err != G_IO_ERROR_NONE)
            g_warning("Seek error");
    }

    watch = g_io_add_watch(
        iochannel, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
        file_read_data, t);
    t->proto_data = GINT_TO_POINTER(watch);

    g_io_channel_unref(iochannel);

    return 0;
} /* file_open */

static void
http_done(SoupMessage *message, gpointer user_data)
{
    RCDTransfer *transfer = user_data;
    RCDTransferError gte;
    char *gte_msg = NULL;

#if 0
    /* FIXME */
    rc_debug(RC_DEBUG_LEVEL_DEBUG, "[%p]: http_done called\n", message);
    rc_debug(RC_DEBUG_LEVEL_DEBUG,
             "[%p]: Soup Error code: %d\n", message, err);
#endif

    /* The transfer was paused... */
    if (transfer->paused)
        return;

    /* If the transfer is cached, read it from there now. */
    if (transfer->cached) {
        char *filename;

        filename = rcd_cache_get_cache_filename(
            transfer->cache, transfer->filename);
        g_free(transfer->url);
        transfer->url = g_strdup_printf("file://%s", filename);
        g_free(filename);
        
        rc_debug(RC_DEBUG_LEVEL_DEBUG, 
                 "[%p]: Reading from the cache: %s",
                 message, transfer->url);
        
        file_open(transfer, 0);

        return;
    }

#ifdef FIXME_PLEASE
    if (message->response_code && message->response_phrase) {
        gte_msg = g_strdup_printf(
            "%d %s", message->response_code, message->response_phrase);
    }

    /* Mapping of Soup errors to RCDTransfer errors. They're very similar... */
    if (err == SOUP_ERROR_CANCELLED)
        gte = RCD_TRANSFER_ERROR_CANCELLED;
    else if (message->response_code == 404)
        gte = RCD_TRANSFER_ERROR_FILE_NOT_FOUND;
    else if (err == SOUP_ERROR_IO)
        gte = RCD_TRANSFER_ERROR_IO;
    else if (err == SOUP_ERROR_MALFORMED_HEADER) {
        gte = RCD_TRANSFER_ERROR_IO;
        gte_msg = g_strdup("Malformed HTTP header");
    }
    else if (err == SOUP_ERROR_CANT_AUTHENTICATE ||
             HTTP_RESPONSE_AUTH_FAILURE(message->response_code))
        gte = RCD_TRANSFER_ERROR_CANT_AUTHENTICATE;
    else if (err == SOUP_ERROR_CANT_CONNECT) {
        rc_debug(RC_DEBUG_LEVEL_DEBUG,
                 "[%p]: SOUP_ERROR_CANT_CONNECT\n", message);
        gte = RCD_TRANSFER_ERROR_CANT_CONNECT;
        /* CANT_CONNECT && !gte_msg signify a DNS failure or a refused conn */
        if (!gte_msg)
            gte_msg = g_strdup("DNS failure or connection refused");
    }
    else if (err == SOUP_ERROR_HANDLER) {
        rc_debug(RC_DEBUG_LEVEL_DEBUG,
                 "[%p]: SOUP_ERROR_HANDLER\n", message);
        gte = RCD_TRANSFER_ERROR_CANT_CONNECT;
    }
    else
#endif
        gte = RCD_TRANSFER_ERROR_NONE;

#ifdef FIXME_PLEASE
    /* This is a workaround what seems to be a bug in Soup, but I am having
     * a tough time tracking it down in the Soup code...  If we make a
     * regular HTTP request to an HTTPS port (ie, the remote end drops the
     * connection immediately following a request, Soup requeues it.
     * What ultimately happens, though, is that we get a call only to
     * this function, with no error but also no data.  I should think that
     * it would return an IO error or CANT_CONNECT, but it doesn't.
     *
     * So anyway, if transfer->data is NULL but err is SOUP_ERROR_NONE,
     * then set the gte to RCD_TRANSFER_ERROR_CANT_CONNECT
     */

    if (err == SOUP_ERROR_NONE && !transfer->data &&
        !(transfer->flags & RCD_TRANSFER_FLAGS_FLUSH_MEMORY)) {
        rc_debug(RC_DEBUG_LEVEL_DEBUG,
                 "[%p]: SOUP_ERROR_NONE, !transfer->data, !FLUSH_MEM\n",
                 message);
        gte = RCD_TRANSFER_ERROR_CANT_CONNECT;
        gte_msg = g_strdup("Connection prematurely dropped");
    }
#endif

    if (is_cacheable(transfer) &&
        rcd_cache_is_active(transfer->cache, transfer->filename)) {
        rcd_cache_close(transfer->cache, transfer->filename);
    }

    rc_debug(RC_DEBUG_LEVEL_DEBUG, "\n\n");

    rcd_transfer_set_error(transfer, gte, gte_msg);
    rcd_transfer_emit_done(transfer);
    g_free(gte_msg);
} /* http_done */

static void
http_content_length(SoupMessage *message, gpointer data)
{
    RCDTransfer *t = data;
    const char *cl;

#ifdef FIXME_PLEASE
    /* Content-Range is present and has already been set. Content-Length is
       only a partial size; the full size is in Content-Range */
    if (t->content_range_set)
        return SOUP_ERROR_NONE;
#endif

    cl = soup_message_get_header(message->response_headers, "Content-Length");
    t->file_size = atoi(cl);

    rc_debug(
        RC_DEBUG_LEVEL_DEBUG, "[%p]: Got Content-Length: %s\n",
        message, cl);
} /* http_content_length */

static void
http_content_range(SoupMessage *message, gpointer data)
{
    RCDTransfer *t = data;
    const char *cr;
    int total;

    cr = soup_message_get_header(message->response_headers, "Content-Range");
    sscanf(cr, "bytes %*d-%*d/%d", &total);
    t->file_size = total;
    t->content_range_set = TRUE;

    rc_debug(
        RC_DEBUG_LEVEL_DEBUG, "[%p]: Got Content-Range: %s\n",
        message, cr);
} /* http_content_range */

static void
http_response_not_modified(SoupMessage *message, gpointer data)
{
    RCDTransfer *t = data;

    rc_debug(
        RC_DEBUG_LEVEL_DEBUG, "[%p]: http_response_not_modified called\n",
        message);

    t->cached = TRUE;
} /* http_response_not_modified */

static void
http_response_ok(SoupMessage *message, gpointer data)
{
    RCDTransfer *t = data;

    rc_debug(
        RC_DEBUG_LEVEL_DEBUG, "[%p]: http_response_ok called\n",
        message);

    /* If we asked for a range of bytes and didn't get it... */
    t->partial = FALSE;
} /* http_response_ok */

static void
http_response_partial_content(SoupMessage *message, gpointer data)
{
    RCDTransfer *t = data;

    rc_debug(
        RC_DEBUG_LEVEL_DEBUG, "[%p]: http_partial_content called\n",
        message);

    /* We're getting a partial content body */
    t->partial = TRUE;
} /* http_response_partial_content */

static void
http_info(SoupMessage *message, gpointer data)
{
    RCDTransfer *t = data;

#ifdef FIXME_PLEASE
    /* If there is an authentication problem, let's just drop it for now.
       Soup has internal handlers that will fix this on its own. */
    if (HTTP_RESPONSE_AUTH_FAILURE(message->response_code))
        return;
#endif

    rc_debug(RC_DEBUG_LEVEL_DEBUG, "[%p]: http_info called\n", message);
    rc_dump_transfer_info(message);

#ifdef FIXME_PLEASE
    /* If we got a 304 Not Modified from the server, we're just going
       to return quietly here, since it'll be pulled from the cache in
       http_done. */
    if (HTTP_RESPONSE_NOT_MODIFIED(message->response_code))
        return;

    /* We only want to do this on success... */
    if (!HTTP_RESPONSE_SUCCESSFUL(message->response_code)) {
        rc_debug(RC_DEBUG_LEVEL_DEBUG,
                 "[%p]: http_info - unsuccessful response code: "
                 "%d, setting HANDLER\n", message, message->response_code);
        return;
    }
#endif

    if (is_cacheable(t))
        rcd_cache_open(t->cache, t->filename, t->offset ? TRUE : FALSE);

    rcd_transfer_file_info(t);
} /* http_info */

static void
http_read_data(SoupMessage *message, gpointer data)
{
    RCDTransfer *t = data;

#ifdef FIXME_PLEASE
    /* If there is an authentication problem, let's just drop it for now.
       Soup has internal handlers that will fix this on its own. */
    if (HTTP_RESPONSE_AUTH_FAILURE(message->response_code))
        return;

    if (!HTTP_RESPONSE_SUCCESSFUL(message->response_code)) {
        rc_debug(RC_DEBUG_LEVEL_DEBUG, 
                 "[%p]: http_read_data - unsuccessful response code: "
                 "%d, setting HANDLER\n", message, message->response_code);
        return;
    }
#endif

    if (is_cacheable(t)) {
        rcd_cache_append(
            t->cache, t->filename,
            message->response.body, message->response.length);
    }

    rcd_transfer_emit_data(
        t, message->response.body, message->response.length);
} /* http_read_data */

static void
http_pause(RCDTransfer *t)
{
    SoupMessage *message = t->proto_data;

    rc_debug(RC_DEBUG_LEVEL_DEBUG, "PAUSE! Trans size: %d\n", t->trans_size);

    soup_message_cancel(message);

    t->proto_data = NULL;

    t->offset = t->trans_size + t->offset;
    t->trans_size = 0;
} /* http_pause */

static void
http_abort(RCDTransfer *t)
{
    SoupMessage *message = t->proto_data;

    if (message)
        soup_message_cancel(message);

    if (is_cacheable(t) && rcd_cache_is_active(t->cache, t->filename))
        rcd_cache_invalidate(t->cache, t->filename);

    t->proto_data = NULL;

    rcd_transfer_set_error(t, RCD_TRANSFER_ERROR_CANCELLED, NULL);
    rcd_transfer_emit_done(t);
} /* http_abort */

static int
http_open(RCDTransfer *t, int offset)
{
    SoupContext *context;
    SoupMessage *message;

#ifdef ALLOW_RCX
    if (rcd_prefs_get_priority ()) {
        SoupUri *uri = rc_rcd_priority_authorized_url(t->url);

        if (!uri) {
            rcd_transfer_set_error(t, RCD_TRANSFER_ERROR_INVALID_URI, t->url);
            return -1;
        }

        context = soup_context_from_uri(uri);
        soup_uri_free(uri);
    }
    else
#endif
        context = soup_context_get(t->url);

    /* No context?  Probably a bad URL. */
    if (!context) {
        rcd_transfer_set_error(t, RCD_TRANSFER_ERROR_INVALID_URI, t->url);
        return -1;
    }

    message = soup_message_new(context, SOUP_METHOD_GET);

    t->proto_data = message;

    if (rcd_prefs_get_http10_enabled())
        soup_message_set_http_version(message, SOUP_HTTP_1_0);

    if (!offset && t->flags & RCD_TRANSFER_FLAGS_RESUME_PARTIAL) {
        char *cache_fn;
        char *cache_tmp;

        cache_fn = rcd_cache_get_cache_filename(t->cache, t->filename);
        cache_tmp = g_strdup_printf("%s.tmp", cache_fn);

        rc_debug(
            RC_DEBUG_LEVEL_DEBUG,
            "[%p]: Trying to find a file to resume... ",
            message);

        if (g_file_test(cache_tmp, G_FILE_TEST_EXISTS)) {
            struct stat s;

            stat(cache_tmp, &s);

            t->offset = offset = s.st_size;

            rc_debug(
                RC_DEBUG_LEVEL_DEBUG, "Found it! File %s, size %d\n",
                cache_tmp, offset);
        }
        else {
            rc_debug(RC_DEBUG_LEVEL_DEBUG, "Not found\n");
        }

        g_free(cache_fn);
        g_free(cache_tmp);
    }

    if (offset) {
        char *range = g_strdup_printf("bytes=%d-", offset);

        t->offset = offset;
        soup_message_add_header(message->request_headers, "Range", range);
    }

    if (!offset && rcd_prefs_get_cache_enabled()) {
        const char *modtime;

        modtime = rcd_cache_get_modification_time(t->cache, t->filename);
        if (modtime) {
            /* We want to get a 304 if we already have the file */
            soup_message_add_header(
                message->request_headers, "If-Modified-Since", modtime);

            /* Handler for 304 Not Modified messages */
            soup_message_add_error_code_handler(
                message, 304, SOUP_HANDLER_PRE_BODY,
                http_response_not_modified, t);
        }
    }

    /* We want to get the chunks out seperately */
    soup_message_set_flags(message, SOUP_MESSAGE_OVERWRITE_CHUNKS);

    /* Handler for normal 200 OK messages */
    soup_message_add_error_code_handler(
        message, 200, SOUP_HANDLER_PRE_BODY, http_response_ok, t);

    /* Handler for 206 Partial Content messages */
    soup_message_add_error_code_handler(
        message, 206, SOUP_HANDLER_PRE_BODY, http_response_partial_content, t);

    soup_message_add_header_handler(
        message, "Content-Length", SOUP_HANDLER_PRE_BODY,
        http_content_length, t);

    soup_message_add_header_handler(
        message, "Content-Range", SOUP_HANDLER_PRE_BODY,
        http_content_range, t);

    soup_message_add_handler(
        message, SOUP_HANDLER_PRE_BODY, http_info, t);

    soup_message_add_handler(
        message, SOUP_HANDLER_BODY_CHUNK,
        http_read_data, t);

    soup_message_add_header(
        message->request_headers, "User-Agent", "Red Carpet/"VERSION);

    rc_debug(
        RC_DEBUG_LEVEL_DEBUG, "[%p]: Queuing up new transfer\n",
        message);

    soup_context_unref(context);
    soup_message_queue(message, http_done, t);

    return 0;
} /* http_open */

typedef int (*RCDTransferOpenFunc)(RCDTransfer *t, int offset);
typedef void (*RCDTransferFunc)(RCDTransfer *t);

typedef struct {
    const char *identifier;
    gboolean    cacheable;

    RCDTransferOpenFunc       open_func;
    RCDTransferFunc           abort_func;
    RCDTransferFunc           pause_func;
} RCDTransferVTable;

RCDTransferVTable rcd_transfer_vtable[] = {
    { "http",  TRUE,  http_open, http_abort, http_pause },
    { "https", TRUE,  http_open, http_abort, http_pause },
    { "file",  FALSE, file_open, file_abort, file_pause },
    { NULL },
};

static RCDTransferVTable *
rcd_transfer_get_vtable_from_url(const char *url)
{
    RCDTransferVTable *v;

    g_return_val_if_fail(url, NULL);

    v = rcd_transfer_vtable;
    while (v->identifier) {
        if (g_strncasecmp(url, v->identifier, strlen(v->identifier)) == 0)
            return v;

        v++;
    }

    g_warning("No idea how to handle URL: %s", url);
    return NULL;
} /* rcd_transfer_get_vtable_from_url */

static RCDTransferVTable *
rcd_transfer_get_vtable(RCDTransfer *t)
{
    g_return_val_if_fail(t, NULL);
    g_return_val_if_fail(RCD_IS_TRANSFER(t), NULL);
    g_return_val_if_fail(t->url, NULL);

    return rcd_transfer_get_vtable_from_url(t->url);
} /* rcd_transfer_get_vtable */

static void
file_data_cb (RCDTransfer *t, char *buf, int size, gpointer user_data)
{
    RCDPending *pending = user_data;
    double perc;

    if (t->file_size > 0)
        perc = 100.0 * (t->trans_size / (double) t->file_size);
    else
        perc = 50.0; /* FIXME! */

    rcd_pending_update (pending, perc);
}

static void
file_done_cb (RCDTransfer *t, gpointer user_data)
{
    RCDPending *pending = user_data;

    rcd_pending_finished (pending, 0);
}

gint
rcd_transfer_begin(RCDTransfer *t, const char *url)
{
    RCDTransferVTable *vtable;
    gchar *desc;
    int rc;
    
    g_return_val_if_fail(RCD_IS_TRANSFER(t), -1);
    g_return_val_if_fail(url && *url, -1);

    vtable = rcd_transfer_get_vtable_from_url(url);
    if (!vtable) {
        rcd_transfer_set_error(t, RCD_TRANSFER_ERROR_INVALID_URI, url);
        return -1;
    }

    t->url = g_strdup(url);
    /* Ew. */
    t->filename = g_strdup(strchr(url + strlen(vtable->identifier) + 3, '/'));
    if (!t->filename)
        t->filename = g_strdup(url + strlen(vtable->identifier) + 3);

    /* Reset the offset to make sure nothing icky is going on. */
    t->offset = 0;

    t->cached = FALSE;

    t->cacheable = vtable->cacheable;

    rc_debug(RC_DEBUG_LEVEL_DEBUG, "Transfer URL: %s\n", t->url);

    rc = vtable->open_func(t, 0);
    if (rc) {
        /* An error occurred in the open call. It's the open call's
           responsibility to rcd_transfer_set_error() the appropriate
           error. */
        return -1;
    }

    current_transfers = g_slist_append(current_transfers, t);

    /* Create associated RCPending object */
    if (! (t->flags & (RCD_TRANSFER_FLAGS_BLOCK | RCD_TRANSFER_FLAGS_NO_PENDING))) {

        desc = g_strdup_printf ("Downloading %s", url);
        t->pending = rcd_pending_new (desc);
        g_free (desc);

        g_signal_connect (t,
                          "file_data",
                          (GCallback) file_data_cb,
                          t->pending);

        g_signal_connect (t,
                          "file_done",
                          (GCallback) file_done_cb,
                          t->pending);

        rcd_pending_begin (t->pending);
    }

    return t->pending ? rcd_pending_get_id (t->pending) : -1;
} /* rcd_transfer_begin */

GByteArray *
rcd_transfer_begin_blocking (RCDTransfer *t,
                             const char  *url)
{
    GByteArray *ret;
    gint id;

    g_return_val_if_fail (RCD_IS_TRANSFER (t), NULL);
    g_return_val_if_fail (url && *url, NULL);

    t->flags = t->flags | RCD_TRANSFER_FLAGS_BLOCK;

    id = rcd_transfer_begin (t, url);

    t->blocking_loop = g_main_loop_new (NULL, TRUE);
    g_main_loop_run (t->blocking_loop);

    ret = t->data;
    t->data = NULL;

    /* FIXME: do something smart w/ the id here. */

    return ret;
}

void
rcd_transfer_abort(RCDTransfer *t)
{
    RCDTransferVTable *vtable;

    g_return_if_fail(t);
    g_return_if_fail(RCD_IS_TRANSFER(t));
   
    vtable = rcd_transfer_get_vtable(t);
    g_return_if_fail(vtable);

    t->aborted = TRUE;

    (vtable->abort_func)(t);
} /* rcd_transfer_abort */

void
rcd_transfer_pause(RCDTransfer *t)
{
    RCDTransferVTable *vtable;

    g_return_if_fail(t);
    g_return_if_fail(RCD_IS_TRANSFER(t));
    g_return_if_fail(!t->paused);

    vtable = rcd_transfer_get_vtable(t);
    g_return_if_fail(vtable);

    if (vtable->pause_func) {
        /* Pause it... */
        t->paused = TRUE;
        (vtable->pause_func)(t);
    }
    else {
        g_warning(
            "Pause not implemented for \"%s\" transfer type",
            vtable->identifier);
    }
} /* rcd_transfer_pause */
    
void
rcd_transfer_resume(RCDTransfer *t)
{
    RCDTransferVTable *vtable;

    g_return_if_fail(t);
    g_return_if_fail(RCD_IS_TRANSFER(t));
    g_return_if_fail(t->paused);

    vtable = rcd_transfer_get_vtable(t);
    g_return_if_fail(vtable);

    t->paused = FALSE;

    (vtable->open_func)(t, t->offset);
} /* rcd_transfer_resume */

static void
print_headers(gpointer key, gpointer value, gpointer data)
{
    rc_debug(RC_DEBUG_LEVEL_DEBUG, "   %s: %s\n", (char *) key, (char *) value);
} /* print_headers */

void
rc_dump_transfer_info(SoupMessage *message)
{
    char *url;

    url = soup_uri_to_string(soup_context_get_uri(message->context), FALSE);

    rc_debug(RC_DEBUG_LEVEL_DEBUG,
             "[%p]: Soup URL %s\n", message, url);
    rc_debug(RC_DEBUG_LEVEL_DEBUG,
             "[%p]: Method: %s\n", message, message->method);
    rc_debug(RC_DEBUG_LEVEL_DEBUG,
             "[%p]: HTTP Version: %s\n", message,
             soup_message_get_http_version(message) == SOUP_HTTP_1_0 ? 
             "1.0" : "1.1");
#if 0
    /* FIXME */
    rc_debug(RC_DEBUG_LEVEL_DEBUG,
             "[%p]: HTTP Response code: %d\n", 
             message, message->response_code);
    rc_debug(RC_DEBUG_LEVEL_DEBUG,
             "[%p]: HTTP Response phrase: %s\n",
             message, message->response_phrase ? message->response_phrase :
             "(null)");
#endif
    if (message->request_headers) {
        rc_debug(RC_DEBUG_LEVEL_DEBUG,
                 "[%p]: Request headers:\n", message);
        g_hash_table_foreach(message->request_headers, print_headers, NULL);
    }
    else {
        rc_debug(RC_DEBUG_LEVEL_DEBUG,
                 "[%p]: No request headers\n", message);
    }

    if (message->response_headers) {
        rc_debug(RC_DEBUG_LEVEL_DEBUG,
                 "[%p]: Response headers:\n", message);
        g_hash_table_foreach(message->response_headers, print_headers, NULL);
    }
    else {
        rc_debug(RC_DEBUG_LEVEL_DEBUG,
                 "[%p]: No response headers\n", message);
    }

    g_free(url);
} /* dump_transfer_info */

