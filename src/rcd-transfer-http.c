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

#define HTTP_RESPONSE_AUTH_FAILURE(x) ((x) == 401 || (x) == 407)
#define HTTP_RESPONSE_NOT_MODIFIED(x) ((x) == 304)

#define RCD_SOUP_MESSAGE_IS_ERROR(msg) \
   (SOUP_STATUS_IS_TRANSPORT_ERROR((msg)->status_code) ||   \
    SOUP_STATUS_IS_CLIENT_ERROR((msg)->status_code) ||      \
    SOUP_STATUS_IS_SERVER_ERROR((msg)->status_code))

static GHashTable *rc_auth_header_table = NULL;
static SoupSession *session = NULL;

static void
print_header (gpointer name, gpointer value, gpointer user_data)
{
    rc_debug (RC_DEBUG_LEVEL_DEBUG,
              "[%p]: > %s: %s",
              user_data, (char *) name, (char *) value);
} /* print_header */

static void
http_debug_pre_handler (SoupMessage *message, gpointer user_data)
{
    rc_debug (RC_DEBUG_LEVEL_DEBUG, "[%p]: Receiving response.", message);

    rc_debug (RC_DEBUG_LEVEL_DEBUG,
              "[%p]: > %d %s",
              message,
              message->status_code,
              message->reason_phrase);

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
http_debug_request_handler (SoupMessage *message, gpointer user_data)
{
    const SoupUri *uri = soup_message_get_uri (message);

    rc_debug (RC_DEBUG_LEVEL_DEBUG,
              "[%p]: > %s %s%s%s HTTP/%s",
              message,
              message->method, uri->path,
              uri->query ? "?" : "",
              uri->query ? uri->query : "",
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
    
    rc_debug (RC_DEBUG_LEVEL_DEBUG, "[%p]: Request sent.", message);
}

static void
http_debug (SoupMessage *message)
{
    rc_debug (RC_DEBUG_LEVEL_DEBUG, "[%p]: Request queued", message);

    soup_message_add_handler (message, SOUP_HANDLER_POST_REQUEST,
                              http_debug_request_handler, NULL);
    soup_message_add_handler (message, SOUP_HANDLER_PRE_BODY,
                              http_debug_pre_handler, NULL);
    soup_message_add_handler (message, SOUP_HANDLER_PRE_BODY,
                              http_debug_post_handler, NULL);
} /* http_debug */

static void
map_soup_error_to_rcd_transfer_error (SoupMessage *message, RCDTransfer *t)
{
    const char *soup_err;
    const char *url = NULL;
    char *err;

    soup_err = message->reason_phrase;

    switch (message->status_code) {
    case SOUP_STATUS_CANCELLED:
        rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_CANCELLED, NULL);
        break;
    case SOUP_STATUS_CANT_CONNECT:
        url = t->url;
    case SOUP_STATUS_CANT_CONNECT_PROXY:
        if (!url)
            url = rcd_prefs_get_proxy_url ();

        err = g_strdup_printf ("%s (%s)", soup_err, url);
        rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_CANT_CONNECT, err);
        g_free (err);
        break;

    case SOUP_STATUS_UNAUTHORIZED:
        url = t->url;
    case SOUP_STATUS_PROXY_UNAUTHORIZED:
        if (!url)
            url = rcd_prefs_get_proxy_url ();

        err = g_strdup_printf ("%s (%s)", soup_err, url);
        rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_CANT_AUTHENTICATE, err);
        g_free (err);
        break;

    case SOUP_STATUS_NOT_FOUND:
        rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_FILE_NOT_FOUND, t->url);
        break;

    default:
        err = g_strdup_printf ("Soup error: %s (%d)", soup_err,
                               message->status_code);
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

static gboolean
http_done_real (gpointer user_data)
{
    RCDTransfer *t = user_data;
    RCDTransferProtocolHTTP *protocol =
        (RCDTransferProtocolHTTP *) t->protocol;

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

            if (rcd_transfer_begin (t) < 0) {
                /* Opening the file failed for some reason */
                rcd_transfer_emit_done (t);
            } else {           
                /*
                 * rcd_transfer_begin() takes a ref which is normally
                 * released in rcd_transfer_file_done(), but since
                 * we're doing some evil here, we'll have to manage
                 * the ref manually.
                 */
                g_object_unref (t);
            }
            
            return FALSE;
        }

        if (t->cache_entry && rcd_cache_entry_is_open (t->cache_entry))
            rcd_cache_entry_close (t->cache_entry);
    }
    else {
        if (t->cache_entry)
            rcd_cache_entry_cancel (t->cache_entry);
    }

    rcd_transfer_emit_done (t);

    return FALSE;
}

static void
http_done (SoupMessage *message, gpointer user_data)
{
    RCDTransfer *t = user_data;
    RCDTransferProtocolHTTP *protocol =
        (RCDTransferProtocolHTTP *) t->protocol;

    /*
     * libsoup will free the response headers after we leave this function,
     * so we have to copy them.  Ew.
     */
    if (protocol->response_headers)
        g_hash_table_destroy (protocol->response_headers);
    
    protocol->response_headers = g_hash_table_new_full (g_str_hash,
                                                        g_str_equal,
                                                        g_free, g_free);

    soup_message_foreach_header (message->response_headers,
                                 copy_header_cb, protocol);

    if (RCD_SOUP_MESSAGE_IS_ERROR (message) &&
        !message->status_code != SOUP_STATUS_NOT_MODIFIED)
        map_soup_error_to_rcd_transfer_error (message, t);

    /*
     * It's possible that this gets called from the transfer's open
     * function.  Since we don't want to call rcd_transfer_file_done()
     * before that happens, we defer as much processing as possible
     * until the next time we hit the main loop.
     */
    g_idle_add (http_done_real, user_data);
}

static void
http_content_length(SoupMessage *message, gpointer data)
{
    RCDTransfer *t = data;
    const char *cl;

    cl = soup_message_get_header (message->response_headers, "Content-Length");
    t->file_size = atoi (cl);
} /* http_content_length */

static void
http_etag(SoupMessage *message, gpointer data)
{
    RCDCacheEntry *entry = data;
    const char *etag;

    etag = soup_message_get_header (message->response_headers, "ETag");
    rcd_cache_entry_set_entity_tag (entry, etag);
} /* http_etag */

static void
http_last_modified(SoupMessage *message, gpointer data)
{
    RCDCacheEntry *entry = data;
    const char *last_modified;

    last_modified = soup_message_get_header (message->response_headers,
                                             "Last-Modified");
    rcd_cache_entry_set_modification_time (entry, last_modified);
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

    /* Reset various settings */
    t->file_size = 0;

    if (SOUP_STATUS_IS_SUCCESSFUL (message->status_code) && t->cache_entry)
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

        uri = soup_message_get_uri (message);
        
        g_hash_table_replace (rc_auth_header_table,
                              g_strdup (uri->host),
                              g_strdup (auth_header));
    }
} /* http_info */

static void
http_read_data (SoupMessage *message,
                gpointer     user_data)
{
    RCDTransfer *t = user_data;

    if (SOUP_STATUS_IS_SUCCESSFUL (message->status_code) &&
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
        soup_session_cancel_message (session, protocol->message);
} /* http_abort */

static void
http_authenticate (SoupSession *session, SoupMessage *message,
                   const char *auth_type, const char *auth_realm,
                   char **username, char **password, gpointer user_data)
{
    /* We only want to do digest authentication for end-point auth */
    if (g_strcasecmp (auth_type, "Digest") != 0) {
        *username = NULL;
        *password = NULL;
        
        return;
    }
    
    *username = g_strdup (rcd_prefs_get_mid ());
    *password = g_strdup (rcd_prefs_get_secret ());
}

static void
http_message_restarted (SoupMessage *message, gpointer user_data)
{
    RCDTransfer *t = user_data;

    /* Flush any previously fetched data */
    if (t->data) {
        g_byte_array_free (t->data, TRUE);
        t->data = g_byte_array_new ();
    }
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
    const char *proxy_url;

    /* The no_network flag is set with a command-line option in rcd.c */
    if (no_network) {
        rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_NETWORK_DISABLED, NULL);
        return -1;
    }

    protocol = (RCDTransferProtocolHTTP *) t->protocol;

    if (!session)
        session = soup_session_async_new ();

    /* Set up the proxy */
    proxy_url = rcd_prefs_get_proxy_url ();
    if (proxy_url) {
        SoupUri *uri;

        uri = soup_uri_new (proxy_url);

        if (!uri) {
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

        uri->user = g_strdup (rcd_prefs_get_proxy_username ());
        uri->passwd = g_strdup (rcd_prefs_get_proxy_password ());

        g_object_set (session, SOUP_SESSION_PROXY_URI, uri, NULL);
    } else
        g_object_set (session, SOUP_SESSION_PROXY_URI, NULL, NULL);

    /*
     * Set the CA file on the session if requiring verified
     * certificates is set.
     */
    if (rcd_prefs_get_require_verified_certificates ()) {
        g_object_set (session, SOUP_SESSION_SSL_CA_FILE,
                      SHAREDIR "/rcd-ca-bundle.pem", NULL);
    } else
        g_object_set (session, SOUP_SESSION_SSL_CA_FILE, NULL, NULL);

    /* Connect to the authenticate signals */
    g_signal_connect (session, "authenticate",
                      G_CALLBACK (http_authenticate), t);

    protocol->message = soup_message_new (protocol->method, t->url);

    g_signal_connect (protocol->message, "restarted",
                      G_CALLBACK (http_message_restarted), t);

    soup_message_set_request (protocol->message,
                              "application/data", 
                              SOUP_BUFFER_USER_OWNED,
                              protocol->request_body,
                              protocol->request_length);

    if (rcd_prefs_get_http10_enabled ()) {
        soup_message_set_http_version (protocol->message, SOUP_HTTP_1_0);
        soup_message_add_header (protocol->message->request_headers,
                                 "Connection", "close");
    }

    /* We want to get the chunks out seperately */
    soup_message_set_flags (protocol->message, SOUP_MESSAGE_OVERWRITE_CHUNKS);

    if (t->cache_entry && (t->flags & RCD_TRANSFER_FLAGS_FORCE_CACHE ||
        (rcd_prefs_get_cache_enabled () &&
         !(t->flags & RCD_TRANSFER_FLAGS_DONT_CACHE)))) {
        const char *modtime;
        const char *entity_tag;

        modtime = rcd_cache_entry_get_modification_time (t->cache_entry);
        entity_tag = rcd_cache_entry_get_entity_tag (t->cache_entry);

        if (modtime || entity_tag) {
            /* Handler for 304 Not Modified messages */
            soup_message_add_status_code_handler (
                protocol->message, SOUP_STATUS_NOT_MODIFIED,
                SOUP_HANDLER_PRE_BODY, http_response_not_modified, t);
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
            protocol->message, "ETag", SOUP_HANDLER_PRE_BODY,
            http_etag, t->cache_entry);

        soup_message_add_header_handler (
            protocol->message, "Last-Modified", SOUP_HANDLER_PRE_BODY,
            http_last_modified, t->cache_entry);
    }

#if 0
    /* Handler for normal 200 OK messages */
    soup_message_add_status_code_handler (
        protocol->message, 200, SOUP_HANDLER_PRE_BODY,
        http_response_ok, t);

    /* Handler for 206 Partial Content messages */
    soup_message_add_status_code_handler (
        protocol->message, 206, SOUP_HANDLER_PRE_BODY,
        http_response_partial_content, t);
#endif

    soup_message_add_header_handler (
        protocol->message, "Content-Length", SOUP_HANDLER_PRE_BODY,
        http_content_length, t);

#if 0
    soup_message_add_header_handler (
        protocol->message, "Content-Range", SOUP_HANDLER_PRE_BODY,
        http_content_range, t);
#endif

    soup_message_add_handler (
        protocol->message, SOUP_HANDLER_PRE_BODY, http_info, t);

    soup_message_add_handler (
        protocol->message, SOUP_HANDLER_BODY_CHUNK,
        http_read_data, t);

    soup_message_add_header (
        protocol->message->request_headers, "User-Agent",
        "Red Carpet Daemon/"VERSION);

    if (rc_auth_header_table) {
        const SoupUri *uri;
        const char *auth_header;

        uri = soup_message_get_uri (protocol->message);
        
        auth_header = g_hash_table_lookup (rc_auth_header_table, uri->host);

        if (auth_header) {
            soup_message_add_header (protocol->message->request_headers,
                                     "X-RC-Auth", auth_header);
        }
    }

    if (protocol->request_headers) {
        g_hash_table_foreach (protocol->request_headers,
                              add_header_cb, protocol->message);
    }
    
    http_debug (protocol->message);

    soup_session_queue_message (session, protocol->message, http_done, t);

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
