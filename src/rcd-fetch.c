/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-fetch.c
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
#include "rcd-fetch.h"

#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include <libredcarpet.h>
#include "rcd-cache.h"
#include "rcd-mirror.h"
#include "rcd-prefs.h"
#include "rcd-transaction.h"
#include "rcd-transfer.h"
#include "rcd-transfer-http.h"
#include "rcd-transfer-pool.h"

#define RCX_ACTIVATION_ROOT "https://activation.rc.ximian.com"

static void
write_file_contents (const char *filename, const GByteArray *data)
{
    char *dir;
    int fd;

    dir = g_path_get_dirname (filename);
    if (!g_file_test (dir, G_FILE_TEST_EXISTS) && rc_mkdir (dir, 0755) < 0) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Couldn't create '%s'", dir);
        g_free (dir);
        return;
    }
    g_free (dir);

    fd = open (filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Couldn't open '%s' for writing", filename);
        return;
    }

    rc_write (fd, data->data, data->len);

    rc_close (fd);
} /* write_file_contents */

gboolean
rcd_fetch_register (const char  *activation_code,
                    const char  *email,
                    const char  *alias,
                    char       **err_msg)
{
    const char *server;
    char *url;
    struct utsname uname_buf;
    const char *hostname;
    RCDTransfer *t;
    RCDTransferProtocolHTTP *protocol;
    const char *status;
    const GByteArray *data;
    gboolean success = TRUE;

    if (err_msg)
        *err_msg = NULL;

    if (uname (&uname_buf) < 0) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Couldn't get hostname from uname()");
        hostname = "(unknown)";
    }
    else
        hostname = uname_buf.nodename;

    server = getenv ("RCD_ACTIVATION_ROOT");
    if (!server) {
        /*
         * If premium services are enabled, we want to activate against our
         * running server.  If not, then the user is using the Red Carpet free
         * service and wants to activate to get RCX service, and we use that
         * URL.
         */

        if (rcd_prefs_get_premium ())
            server = rcd_prefs_get_host ();
        else
            server = RCX_ACTIVATION_ROOT;
    }

    /*
     * If we're activating, we don't have an orgtoken; that information is
     * tied to the activation code.
     */
    if (!activation_code) {
        g_assert (rcd_prefs_get_org_id ());
        url = g_strdup_printf ("%s/register.php?orgtoken=%s&hostname=%s",
                               server, rcd_prefs_get_org_id (), hostname);
    }
    else {
        url = g_strdup_printf ("%s/register.php?hostname=%s",
                               server, hostname);
    }

    t = rcd_transfer_new (url, 0, NULL);
    g_free (url);

    /* If the protocol isn't HTTP, forget about it */
    /* FIXME: Should we send out a warning here? */
    if (!t->protocol || strcmp (t->protocol->name, "http") != 0)
        return FALSE;

    protocol = (RCDTransferProtocolHTTP *) t->protocol;

    rcd_transfer_protocol_http_set_request_header (
        protocol, "X-RC-MID", rcd_prefs_get_mid ());

    rcd_transfer_protocol_http_set_request_header (
        protocol, "X-RC-Secret", rcd_prefs_get_secret ());

    if (activation_code) {
        rcd_transfer_protocol_http_set_request_header (
            protocol, "X-RC-Activation", activation_code);
    }

    if (email) {
        rcd_transfer_protocol_http_set_request_header (
            protocol, "X-RC-Email", email);
    }

    if (alias) {
        rcd_transfer_protocol_http_set_request_header (
            protocol, "X-RC-Alias", alias);
    }

    data = rcd_transfer_begin_blocking (t);

    status = rcd_transfer_protocol_http_get_response_header (protocol,
                                                             "X-RC-Status");
    if (!status || atoi (status) != 1) {
        const char *msg;

        if (rcd_transfer_get_error (t))
            msg = rcd_transfer_get_error_string (t);
        else {
            msg = rcd_transfer_protocol_http_get_response_header (protocol,
                                                                  "X-RC-Error");
        }

        if (msg) {
            rc_debug (RC_DEBUG_LEVEL_WARNING,
                      "Unable to register with server: %s", msg);
        }
        else {
            rc_debug (RC_DEBUG_LEVEL_WARNING,
                      "Unable to register with server");
        }

        if (err_msg)
            *err_msg = g_strdup (msg);

        success = FALSE;
    }
    else {
        const char *new_host;

        rc_debug (RC_DEBUG_LEVEL_INFO, "System registered successfully");

        new_host =
            rcd_transfer_protocol_http_get_response_header (protocol,
                                                            "X-RC-Host");

        if (new_host) {
            rc_debug (RC_DEBUG_LEVEL_INFO, "Setting new host to %s", new_host);
            rcd_prefs_set_host (new_host);
            rcd_prefs_set_premium (TRUE);
        }
    }

    g_object_unref (t);

    return success;
} /* rcd_fetch_register */

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

#if 0
static char *
merge_paths (const char *parent_path, const char *child_path)
{
    SoupUri *parent_url;
    SoupUri *child_url;
    char *ret;

    g_return_val_if_fail (parent_path, NULL);

    if (!child_path)
        return g_strdup (parent_path);

    parent_url = soup_uri_new (parent_path);
    child_url = soup_uri_new (child_path);

    if (child_url)
        ret = g_strdup (child_path);
    else {
        if (!parent_url) {
            if (parent_path[strlen(parent_path) - 1] == '/')
                ret = g_strconcat (parent_path, child_path, NULL);
            else
                ret = g_strconcat (parent_path, "/", child_path, NULL);
        }
        else {
            if (child_path[0] == '/') {
                g_free (parent_url->path);
                parent_url->path = g_strdup(child_path);
                ret = soup_uri_to_string (parent_url, TRUE);
            }
            else {
                if (parent_path[strlen(parent_path) - 1] == '/')
                    ret = g_strconcat (parent_path, child_path, NULL);
                else
                    ret = g_strconcat (parent_path, "/", child_path, NULL);
            }
        }
    }

    if (parent_url)
        soup_uri_free (parent_url);

    if (child_url)
        soup_uri_free (child_url);

    return ret;
}
#endif

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static void
package_completed_cb (RCDTransfer *t, RCPackage *package)
{
    /* Ew. */
    if (g_object_get_data (G_OBJECT (t), "is_signature"))
        package->signature_filename = rcd_transfer_get_local_filename (t);
    else
        package->package_filename = rcd_transfer_get_local_filename (t);
}

void
rcd_fetch_packages (RCDTransferPool *pool, RCPackageSList *packages)
{
    RCPackageSList *iter;

    g_return_if_fail (pool != NULL);
    g_return_if_fail (packages != NULL);

    for (iter = packages; iter; iter = iter->next) {
        RCPackage *package = iter->data;
        RCPackageUpdate *update = rc_package_get_latest_update (package);
        RCWorldService *service;
        char *url;
        RCDCacheEntry *entry;
        RCDTransfer *t;

        service = RC_WORLD_SERVICE (rc_channel_get_world (package->channel));

        url = rc_maybe_merge_paths (service->url, update->package_url);

        entry = rcd_cache_lookup_by_url (rcd_cache_get_package_cache (),
                                         url, TRUE);
        t = rcd_transfer_new (url,
                              RCD_TRANSFER_FLAGS_FORCE_CACHE |
                              RCD_TRANSFER_FLAGS_RESUME_PARTIAL,
                              entry);

        g_signal_connect (t, "file_done",
                          G_CALLBACK (package_completed_cb), package);

        rcd_transfer_pool_add_transfer (pool, t);
        g_object_unref (t);

        if (update->signature_url) {
            url = rc_maybe_merge_paths (service->url, update->signature_url);

            entry = rcd_cache_lookup_by_url (rcd_cache_get_package_cache (),
                                             url, TRUE);
        
            t = rcd_transfer_new (url,
                                  RCD_TRANSFER_FLAGS_FORCE_CACHE |
                                  RCD_TRANSFER_FLAGS_RESUME_PARTIAL,
                                  entry);

            /* Ew. */
            g_object_set_data (G_OBJECT (t), "is_signature",
                               GINT_TO_POINTER (TRUE));

            g_signal_connect (t, "file_done",
                              G_CALLBACK (package_completed_cb), package);

            rcd_transfer_pool_add_transfer (pool, t);
            g_object_unref (t);
        }
    }
}
