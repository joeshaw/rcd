/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-transfer-http.c
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

#include <config.h>
#include "rcd-transfer-http.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <libredcarpet.h>

#include "rcd-prefs.h"

/* 
 * FIXME:
 *   - Proxies: Need to write the code in rcd-prefs.c to get a URL and
 *     uncomment the code.
 *   - RCD: Ditto.
 *   - Resuming partial transfers: Need to write
 */

#define HTTP_RESPONSE_SUCCESSFUL(x)   ((x) >= 200 && (x) < 300)
#define HTTP_RESPONSE_REDIRECT(x)     ((x) >= 300 && (x) < 400)
#define HTTP_RESPONSE_CLIENT_ERROR(x) ((x) >= 400 && (x) < 400)
#define HTTP_RESPONSE_SERVER_ERROR(x) ((x) >= 500 && (x) < 600)

#define HTTP_RESPONSE_AUTH_FAILURE(x) ((x) == 401 || (x) == 407)
#define HTTP_RESPONSE_NOT_MODIFIED(x) ((x) == 304)

static void
http_done (SoupMessage *message, gpointer user_data)
{
    RCDTransfer *t = user_data;
    RCDTransferProtocolHTTP *protocol =
        (RCDTransferProtocolHTTP *) t->protocol;

    /* Map Soup errors to RCDTransfer errors. */
    if (SOUP_MESSAGE_IS_ERROR (message)) {
        if (message->errorcode == SOUP_ERROR_CANT_AUTHENTICATE)
            rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_CANT_AUTHENTICATE, NULL);
        else if (message->errorcode == SOUP_ERROR_CANT_AUTHENTICATE_PROXY)
            rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_CANT_AUTHENTICATE, NULL);
        else if (message->errorcode == SOUP_ERROR_NOT_FOUND)
            rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_FILE_NOT_FOUND, t->url);
        else {
            char *err = g_strdup_printf (
                "Soup error: %s (%d)",
                soup_error_get_phrase (message->errorcode),
                message->errorcode);
            rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_IO, err);
            g_free (err);
        }
    }

    if (!rcd_transfer_get_error (t)) {
        if (protocol->cache_hit) {
            char *cache_filename;
            char *local_url;
            
            cache_filename =
                rcd_cache_entry_get_local_filename (protocol->entry);
            local_url = g_strconcat ("file://", cache_filename, NULL);
            g_free (cache_filename);
            
            g_free (protocol);
            g_free (t->url);
            g_free (t->filename);
            
            rcd_transfer_begin (t, local_url);
            g_free (local_url);
            
            return;
        }

        if (protocol->entry)
            rcd_cache_entry_close (protocol->entry);
    }
    else {
        if (protocol->entry)
            rcd_cache_entry_cancel (protocol->entry);
    }

    rcd_transfer_emit_done (t);
} /* http_done */

static void
http_content_length(SoupMessage *message, gpointer data)
{
    RCDTransfer *t = data;
    const char *cl;

    cl = soup_message_get_header (message->response_headers, "Content-Length");
    t->file_size = atoi (cl);

    rc_debug (
        RC_DEBUG_LEVEL_DEBUG, "[%p]: Got Content-Length: %s\n",
        message, cl);
} /* http_content_length */

static void
http_etag(SoupMessage *message, gpointer data)
{
    RCDCacheEntry *entry = data;
    const char *etag;

    etag = soup_message_get_header (message->response_headers, "ETag");
    rcd_cache_entry_set_entity_tag (entry, etag);

    rc_debug (
        RC_DEBUG_LEVEL_DEBUG, "[%p]: Got ETag: %s\n",
        message, etag);
} /* http_etag */

static void
http_last_modified(SoupMessage *message, gpointer data)
{
    RCDCacheEntry *entry = data;
    const char *last_modified;

    last_modified = soup_message_get_header (message->response_headers,
                                             "Last-Modified");
    rcd_cache_entry_set_modification_time (entry, last_modified);

    rc_debug (
        RC_DEBUG_LEVEL_DEBUG, "[%p]: Got Last-Modified: %s\n",
        message, last_modified);
} /* http_last_modified */

static void
http_response_not_modified (SoupMessage *message, gpointer data)
{
    RCDTransfer *t = data;
    RCDTransferProtocolHTTP *protocol =
        (RCDTransferProtocolHTTP *) t->protocol;

    protocol->cache_hit = TRUE;
} /* http_response_not_modified */

static void
http_info (SoupMessage *message,
           gpointer     user_data)
{
    RCDTransfer *t = user_data;
    RCDTransferProtocolHTTP *protocol =
        (RCDTransferProtocolHTTP *) t->protocol;

    if (!HTTP_RESPONSE_NOT_MODIFIED (message->errorcode) &&
        !HTTP_RESPONSE_AUTH_FAILURE (message->errorcode) &&
        protocol->entry)
        rcd_cache_entry_open (protocol->entry);

    rc_debug (RC_DEBUG_LEVEL_DEBUG, "[%p]: http_info called", message);
} /* http_info */

static void
http_read_data (SoupMessage *message,
                gpointer     user_data)
{
    RCDTransfer *t = user_data;
    RCDTransferProtocolHTTP *protocol =
        (RCDTransferProtocolHTTP *) t->protocol;

    if (protocol->entry) {
        rcd_cache_entry_append (
            protocol->entry, message->response.body, message->response.length);
    }

    rcd_transfer_emit_data (
        t, message->response.body, message->response.length);
} /* http_read_data */

static void
http_abort (RCDTransfer *t)
{
    RCDTransferProtocolHTTP *protocol =
        (RCDTransferProtocolHTTP *) t->protocol;

    rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_CANCELLED, NULL);

    if (protocol->message)
        soup_message_cancel (protocol->message);
} /* http_abort */

static char *
get_mid (void)
{
    RCBuffer *buf;
    char *mid;

    buf = rc_buffer_map_file (SYSCONFDIR "/mcookie");
    if (!buf)
        return NULL;

    mid = g_strndup (buf->data, 36);
    mid[36] = '\0';

    rc_buffer_unmap_file (buf);

    return mid;
} /* get_mid */

static char *
get_secret (void)
{
    RCBuffer *buf;
    char *secret;

    buf = rc_buffer_map_file (SYSCONFDIR "/partnernet");
    if (!buf)
        return NULL;

    secret = g_strndup (buf->data, 36);
    secret[36] = '\0';

    rc_buffer_unmap_file (buf);

    return secret;
} /* get_secret */

static SoupUri *
get_premium_uri (const char *url)
{
    SoupUri *uri;

    uri = soup_uri_new (url);

    /* An invalid URL was passed to us */
    if (!uri)
        return NULL;

    uri->user = get_mid ();
    uri->passwd = get_secret ();

    return uri;
} /* get_premium_uri */

static int
http_open (RCDTransfer *t)
{
    RCDTransferProtocolHTTP *protocol;
    SoupUri *uri;
    SoupContext *context;
    SoupMessage *message;
#if 0
    const char *proxy_url;
    SoupContext *proxy_context;
#endif

    protocol = (RCDTransferProtocolHTTP *) t->protocol;

    if (rcd_prefs_get_premium ())
        uri = get_premium_uri (t->url);
    else
        uri = soup_uri_new (t->url);

    context = soup_context_from_uri (uri);

    /* No context?  Probably a bad URL. */
    if (!context) {
        rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_INVALID_URI, t->url);
        soup_uri_free (uri);
        return -1;
    }
    
    protocol->message = message = soup_message_new (context, SOUP_METHOD_GET);

    /* Set up the proxy */
    /* FIXME: Get the proxy pref */
#if 0
    proxy_url = rcd_pregs_get_proxy_url ();
    if (proxy_url) {
        proxy_context = soup_context_get (proxy_url);
        soup_set_proxy (proxy_context);
    }
    else
#endif
        soup_set_proxy (NULL);

    if (rcd_prefs_get_http10_enabled ())
        soup_message_set_http_version (protocol->message, SOUP_HTTP_1_0);

    /* We want to get the chunks out seperately */
    soup_message_set_flags (message, SOUP_MESSAGE_OVERWRITE_CHUNKS);

    if (t->flags & RCD_TRANSFER_FLAGS_FORCE_CACHE ||
        (rcd_prefs_get_cache_enabled () &&
         !(t->flags & RCD_TRANSFER_FLAGS_DONT_CACHE))) {
        protocol->entry = rcd_cache_lookup (t->cache, t->url);

        if (protocol->entry) {
            const char *modtime;
            const char *entity_tag;

            modtime = rcd_cache_entry_get_modification_time (protocol->entry);
            entity_tag = rcd_cache_entry_get_entity_tag (protocol->entry);

            if (modtime || entity_tag) {
                /* Handler for 304 Not Modified messages */
                soup_message_add_error_code_handler (
                    message, 304, SOUP_HANDLER_PRE_BODY,
                    http_response_not_modified, t);
            }

            if (modtime) {
                /* We want to get a 304 if we already have the file */
                soup_message_add_header (
                    protocol->message->request_headers,
                    "If-Modified-Since", modtime);
            }

            if (entity_tag) {
                /* We want to get a 304 if we already have the file */
                soup_message_add_header (
                    protocol->message->request_headers,
                    "If-None-Match", entity_tag);
            }
        }
        else
            protocol->entry = rcd_cache_entry_new (t->cache, t->url);

        soup_message_add_header_handler (
            message, "ETag", SOUP_HANDLER_PRE_BODY,
            http_etag, protocol->entry);

        soup_message_add_header_handler (
            message, "Last-Modified", SOUP_HANDLER_PRE_BODY,
            http_last_modified, protocol->entry);
    }

#if 0
    /* Handler for normal 200 OK messages */
    soup_message_add_error_code_handler (
        message, 200, SOUP_HANDLER_PRE_BODY, http_response_ok, t);

    /* Handler for 206 Partial Content messages */
    soup_message_add_error_code_handler (
        message, 206, SOUP_HANDLER_PRE_BODY, http_response_partial_content, t);
#endif

    soup_message_add_header_handler (
        message, "Content-Length", SOUP_HANDLER_PRE_BODY,
        http_content_length, t);

#if 0
    soup_message_add_header_handler (
        message, "Content-Range", SOUP_HANDLER_PRE_BODY,
        http_content_range, t);
#endif

    soup_message_add_handler (
        message, SOUP_HANDLER_PRE_BODY, http_info, t);

    soup_message_add_handler (
        message, SOUP_HANDLER_BODY_CHUNK,
        http_read_data, t);

    soup_message_add_header (
        message->request_headers, "User-Agent", "Red Carpet Daemon/"VERSION);

    rc_debug (
        RC_DEBUG_LEVEL_DEBUG, "[%p]: Queuing up new transfer\n",
        message);

    soup_context_unref (context);
    soup_message_queue (message, http_done, t);

    soup_uri_free (uri);

    return 0;
} /* http_open */

char *
http_get_local_filename (RCDTransfer *t)
{
    RCDTransferProtocolHTTP *protocol =
        (RCDTransferProtocolHTTP *) t->protocol;

    if (protocol->entry)
        return rcd_cache_entry_get_local_filename (protocol->entry);
    else
        return NULL;
} /* http_get_filename */

RCDTransferProtocol *
rcd_transfer_protocol_http_new (void)
{
    RCDTransferProtocolHTTP *http_protocol;
    RCDTransferProtocol *protocol;

    http_protocol = g_new0 (RCDTransferProtocolHTTP, 1);
    protocol = (RCDTransferProtocol *) http_protocol;

    protocol->name = "http";

    protocol->get_local_filename_func = http_get_local_filename;
    protocol->open_func = http_open;
    protocol->abort_func = http_abort;

    return protocol;
} /* rcd_transfer_protocol_http_new */
