/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-transfer-http.c
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
#include "rcd-transfer-http.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <libredcarpet.h>

#include "rcd-options.h"
#include "rcd-prefs.h"

/* 
 * TODO:
 *   - Resuming partial transfers: Need to write
 */

#define HTTP_RESPONSE_SUCCESSFUL(x)   ((x) >= 200 && (x) < 300)
#define HTTP_RESPONSE_REDIRECT(x)     ((x) >= 300 && (x) < 400)
#define HTTP_RESPONSE_CLIENT_ERROR(x) ((x) >= 400 && (x) < 400)
#define HTTP_RESPONSE_SERVER_ERROR(x) ((x) >= 500 && (x) < 600)

#define HTTP_RESPONSE_AUTH_FAILURE(x) ((x) == 401 || (x) == 407)
#define HTTP_RESPONSE_NOT_MODIFIED(x) ((x) == 304)

#define RCD_SOUP_MESSAGE_IS_ERROR(msg) \
   msg->errorclass != SOUP_ERROR_CLASS_SUCCESS &&       \
   msg->errorclass != SOUP_ERROR_CLASS_INFORMATIONAL && \
   msg->errorclass != SOUP_ERROR_CLASS_REDIRECT

static GHashTable *rc_auth_header_table = NULL;

static void
print_header (gpointer name, gpointer value, gpointer user_data)
{
    rc_debug (RC_DEBUG_LEVEL_DEBUG,
              "[%p]: %s: %s",
              user_data, (char *) name, (char *) value);
} /* print_header */

static void
http_debug_pre_handler (SoupMessage *message, gpointer user_data)
{
    rc_debug (RC_DEBUG_LEVEL_DEBUG, "[%p]: Receiving response.", message);

    rc_debug (RC_DEBUG_LEVEL_DEBUG,
              "[%p]: %d %s",
              message,
              message->errorcode,
              message->errorphrase);

    soup_message_foreach_header (message->response_headers,
                                 print_header, message);
} /* http_debug_pre_handler */

static void
http_debug_post_handler (SoupMessage *message, gpointer user_data)
{
    if (message->response.length) {
        rc_debug (RC_DEBUG_LEVEL_DEBUG,
                  "[%p]: Response body:\n%.*s\n",
                  message, 
                  (int) message->response.length,
                  message->response.body);
    }

    rc_debug (RC_DEBUG_LEVEL_DEBUG,
              "[%p]: Transfer finished",
              message);
} /* http_debug_post_handler */

static void
http_debug (SoupMessage *message)
{
    const SoupUri *uri = soup_context_get_uri (message->context);

    rc_debug (RC_DEBUG_LEVEL_DEBUG,
              "[%p]: Queuing up new transfer",
              message);

    rc_debug (RC_DEBUG_LEVEL_DEBUG,
              "[%p]: %s %s%s%s HTTP/%s",
              message,
              message->method, uri->path,
              uri->querystring ? "?" : "",
              uri->querystring ? uri->querystring : "",
              rcd_prefs_get_http10_enabled () ? "1.0" : "1.1");

    soup_message_foreach_header (message->request_headers,
                                 print_header, message);

    if (message->request.length) {
        rc_debug (RC_DEBUG_LEVEL_DEBUG,
                  "[%p]: Request body:\n%.*s\n",
                  message, 
                  (int) message->request.length,
                  message->request.body);
    }

    soup_message_add_handler (message, SOUP_HANDLER_PRE_BODY,
                              http_debug_pre_handler, NULL);
    soup_message_add_handler (message, SOUP_HANDLER_PRE_BODY,
                              http_debug_post_handler, NULL);
    
    rc_debug (RC_DEBUG_LEVEL_DEBUG, "[%p]: Request sent.", message);
} /* http_debug */

static void
map_soup_error_to_rcd_transfer_error (SoupMessage *message, RCDTransfer *t)
{
    const char *soup_err;
    const char *url = NULL;
    const char *display_url = NULL;
    char *err;

    soup_err = message->errorphrase;

    switch (message->errorcode) {
    case SOUP_ERROR_CANCELLED:
        rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_CANCELLED, NULL);
        break;
    case SOUP_ERROR_CANT_CONNECT:
        url = display_url = t->url;
    case SOUP_ERROR_CANT_CONNECT_PROXY:
        if (!url) {
            url = rcd_prefs_get_proxy ();
            /* We can't use 'url' because it may contain users's password */
            display_url = rcd_prefs_get_proxy_url ();
        }

        err = g_strdup_printf ("%s (%s)", soup_err, display_url);
        rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_CANT_CONNECT, err);
        g_free (err);
        break;

    case SOUP_ERROR_CANT_AUTHENTICATE:
        url = display_url = t->url;
    case SOUP_ERROR_CANT_AUTHENTICATE_PROXY:
        if (!url) {
            url = rcd_prefs_get_proxy ();
            /* We can't use 'url' because it may contain users's password */
            display_url = rcd_prefs_get_proxy_url ();
        }

        err = g_strdup_printf ("%s (%s)", soup_err, display_url);
        rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_CANT_AUTHENTICATE, err);
        g_free (err);
        break;

    case SOUP_ERROR_NOT_FOUND:
        rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_FILE_NOT_FOUND, t->url);
        break;

    default:
        err = g_strdup_printf (
            "Soup error: %s (%d)", soup_err, message->errorcode);
        rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_IO, err);
        g_free (err);
        break;
    }
} /* map_soup_error_to_rcd_transfer_error */

static void
copy_header_cb (gpointer name, gpointer value, gpointer user_data)
{
    char *header_name = name;
    char *header_value = value;
    RCDTransferProtocolHTTP *protocol = user_data;

    g_hash_table_insert (protocol->response_headers,
                         g_strdup (header_name),
                         g_strdup (header_value));
} /* copy_header_cb */

static void
http_done (SoupMessage *message, gpointer user_data)
{
    RCDTransfer *t = user_data;
    RCDTransferProtocolHTTP *protocol =
        (RCDTransferProtocolHTTP *) t->protocol;

    /*
     * Soup will free the response headers after we leave this function,
     * so we have to copy them.  Ew.
     */
    if (protocol->response_headers)
        g_hash_table_destroy (protocol->response_headers);
    
    protocol->response_headers = g_hash_table_new_full (
        g_str_hash, g_str_equal, g_free, g_free);
    soup_message_foreach_header (
        message->response_headers, copy_header_cb, protocol);

    if (RCD_SOUP_MESSAGE_IS_ERROR (message) &&
        !message->errorcode != SOUP_ERROR_NOT_MODIFIED)
        map_soup_error_to_rcd_transfer_error (message, t);

    if (!rcd_transfer_get_error (t)) {
        if (protocol->cache_hit) {
            char *cache_filename;
            char *local_url;
            
            cache_filename =
                rcd_cache_entry_get_local_filename (t->cache_entry);
            local_url = g_strconcat ("file://", cache_filename, NULL);
            g_free (cache_filename);
            
            g_free (protocol);
            g_free (t->url);
            g_free (t->filename);

            t->protocol = rcd_transfer_get_protocol_from_url (local_url);
            t->url = g_strdup (local_url);
            t->filename = g_path_get_basename (t->url);
            g_free (local_url);
            
            rcd_transfer_begin (t);

            /*
             * rcd_transfer_begin() takes a ref which is normally released
             * in rcd_transfer_file_done(), but since we're doing some
             * evil here, we'll have to manage the ref manually.
             */
            g_object_unref (t);
            
            return;
        }

        if (t->cache_entry && rcd_cache_entry_is_open (t->cache_entry))
            rcd_cache_entry_close (t->cache_entry);
    }
    else {
        if (t->cache_entry)
            rcd_cache_entry_cancel (t->cache_entry);
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
        RC_DEBUG_LEVEL_DEBUG, "[%p]: Got Content-Length: %s",
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
        RC_DEBUG_LEVEL_DEBUG, "[%p]: Got ETag: %s",
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
        RC_DEBUG_LEVEL_DEBUG, "[%p]: Got Last-Modified: %s",
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
    const char *auth_header;

    if (HTTP_RESPONSE_SUCCESSFUL (message->errorcode) && t->cache_entry)
        rcd_cache_entry_open (t->cache_entry);

    auth_header = soup_message_get_header (
        message->response_headers, "X-RC-Auth");

    if (auth_header) {
        const SoupUri *uri;

        if (rc_auth_header_table == NULL) {
            rc_auth_header_table = g_hash_table_new_full (g_str_hash,
                                                          g_str_equal,
                                                          g_free, g_free);
        }

        uri = soup_context_get_uri (message->context);
        
        g_hash_table_replace (rc_auth_header_table,
                              g_strdup (uri->host),
                              g_strdup (auth_header));
    }

    rc_debug (RC_DEBUG_LEVEL_DEBUG, "[%p]: http_info called", message);
} /* http_info */

static void
http_read_data (SoupMessage *message,
                gpointer     user_data)
{
    RCDTransfer *t = user_data;

    if (HTTP_RESPONSE_SUCCESSFUL (message->errorcode) &&
        t->cache_entry && rcd_cache_entry_is_open (t->cache_entry))
    {
        rcd_cache_entry_append (
            t->cache_entry, message->response.body, message->response.length);
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

static SoupUri *
get_uri_with_auth_info (const char *url)
{
    SoupUri *uri;

    uri = soup_uri_new (url);

    /* An invalid URL was passed to us */
    if (!uri)
        return NULL;

    uri->authmech = g_strdup ("Digest");
    uri->user = g_strdup (rcd_prefs_get_mid ());
    uri->passwd = g_strdup (rcd_prefs_get_secret ());

    return uri;
}

static void
add_header_cb (gpointer key, gpointer value, gpointer user_data)
{
    char *header_name = key;
    char *header_value = value;
    SoupMessage *message = user_data;

    soup_message_add_header (message->request_headers, header_name, header_value);
} /* add_header_cb */

static int
http_open (RCDTransfer *t)
{
    gboolean no_network = rcd_options_get_no_network_flag ();
    RCDTransferProtocolHTTP *protocol;
    SoupUri *uri;
    SoupContext *context;
    SoupMessage *message;
    const char *proxy_url;
    SoupContext *proxy_context;

    /* The no_network flag is set with a command-line option in rcd.c */
    if (no_network) {
        rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_NETWORK_DISABLED, NULL);
        return -1;
    }

    protocol = (RCDTransferProtocolHTTP *) t->protocol;

    uri = get_uri_with_auth_info (t->url);

    context = soup_context_from_uri (uri);

    soup_uri_free (uri);

    /* No context?  Probably a bad URL. */
    if (!context) {
        rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_INVALID_URI, t->url);
        return -1;
    }
    
    protocol->message = message = soup_message_new_full (
        context,
        protocol->method,
        SOUP_BUFFER_USER_OWNED,
        protocol->request_body,
        protocol->request_length);

    /* Set up the proxy */
    proxy_url = rcd_prefs_get_proxy ();
    if (proxy_url) {
        proxy_context = soup_context_get (proxy_url);

        /* No context?  Probably a bad URL. */
        if (!proxy_context) {
            char *err_str;

            /* 
             * We can't use 'proxy_url' because it may contain the user's
             * password.
             */
            err_str = g_strconcat("Invalid proxy URL: ",
                                  rcd_prefs_get_proxy_url (), NULL);

            rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_INVALID_URI,
                                    err_str);
            g_free (err_str);
            return -1;
        }

        soup_set_proxy (proxy_context);
    }
    else
        soup_set_proxy (NULL);

    if (rcd_prefs_get_http10_enabled ()) {
        soup_message_set_http_version (protocol->message, SOUP_HTTP_1_0);
        soup_message_add_header (protocol->message->request_headers,
                                 "Connection", "close");
    }

    /* We want to get the chunks out seperately */
    soup_message_set_flags (message, SOUP_MESSAGE_OVERWRITE_CHUNKS);

    if (t->cache_entry && (t->flags & RCD_TRANSFER_FLAGS_FORCE_CACHE ||
        (rcd_prefs_get_cache_enabled () &&
         !(t->flags & RCD_TRANSFER_FLAGS_DONT_CACHE)))) {
        const char *modtime;
        const char *entity_tag;

        modtime = rcd_cache_entry_get_modification_time (t->cache_entry);
        entity_tag = rcd_cache_entry_get_entity_tag (t->cache_entry);

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

        soup_message_add_header_handler (
            message, "ETag", SOUP_HANDLER_PRE_BODY,
            http_etag, t->cache_entry);

        soup_message_add_header_handler (
            message, "Last-Modified", SOUP_HANDLER_PRE_BODY,
            http_last_modified, t->cache_entry);
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

    if (rc_auth_header_table) {
        const SoupUri *uri;
        const char *auth_header;

        uri = soup_context_get_uri (context);
        
        auth_header = g_hash_table_lookup (rc_auth_header_table, uri->host);

        if (auth_header) {
            soup_message_add_header (message->request_headers,
                                     "X-RC-Auth", auth_header);
        }
    }

    if (protocol->request_headers) {
        g_hash_table_foreach (protocol->request_headers,
                              add_header_cb, message);
    }

    soup_context_unref (context);

    http_debug (message);

    soup_message_queue (message, http_done, t);

    return 0;
} /* http_open */

static char *
http_get_local_filename (RCDTransfer *t)
{
    if (t->cache_entry)
        return rcd_cache_entry_get_local_filename (t->cache_entry);
    else
        return NULL;
} /* http_get_filename */

static void
http_free (RCDTransferProtocol *protocol)
{
    RCDTransferProtocolHTTP *http_protocol = 
        (RCDTransferProtocolHTTP *) protocol;

    if (http_protocol->request_headers)
        g_hash_table_destroy (http_protocol->request_headers);

    if (http_protocol->response_headers)
        g_hash_table_destroy (http_protocol->response_headers);

    g_free (protocol);
} /* http_free */

void
rcd_transfer_protocol_http_set_method (RCDTransferProtocolHTTP *protocol,
                                       const char              *method)
{
    g_return_if_fail (protocol);
    g_return_if_fail (method);

    protocol->method = method;
} /* rcd_transfer_protocol_http_set_method */

void
rcd_transfer_protocol_http_set_request_body (RCDTransferProtocolHTTP *protocol,
                                             char                    *body,
                                             gsize                    length)
{
    g_return_if_fail (protocol);
    g_return_if_fail (body);
    g_return_if_fail (length);

    protocol->request_body = body;
    protocol->request_length = length;
}

void
rcd_transfer_protocol_http_set_request_header (RCDTransferProtocolHTTP *protocol,
                                               const char              *header,
                                               const char              *value)
{
    g_return_if_fail (protocol);
    g_return_if_fail (header);
    g_return_if_fail (value);

    if (!protocol->request_headers) {
        protocol->request_headers = g_hash_table_new_full (
            g_str_hash, g_str_equal, g_free, g_free);
    }

    g_hash_table_insert (protocol->request_headers, g_strdup (header), g_strdup (value));
}

const char *
rcd_transfer_protocol_http_get_response_header (RCDTransferProtocolHTTP *protocol,
                                                const char              *header)
{
    g_return_val_if_fail (protocol, NULL);
    g_return_val_if_fail (header, NULL);

    if (!protocol->response_headers) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Trying to get a response header before transfer");
        return NULL;
    }

    return g_hash_table_lookup (protocol->response_headers, header);
} /* rcd_transfer_protocol_http_get_response_header */

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

    protocol->free_func = http_free;

    http_protocol->method = SOUP_METHOD_GET;

    return protocol;
} /* rcd_transfer_protocol_http_new */
