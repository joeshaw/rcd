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
#include "rcd-news.h"
#include "rcd-prefs.h"
#include "rcd-transfer.h"
#include "rcd-transfer-http.h"

#define RCX_ACTIVATION_ROOT "https://activation.rc.ximian.com"

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
    GByteArray *data;
    gboolean success = TRUE;

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

    g_byte_array_free (data, TRUE);

    g_object_unref (t);

    return success;
} /* rcd_fetch_register */

gboolean
rcd_fetch_distro (void)
{
    char *url;
    RCDTransfer *t;
    GByteArray *data;
    gboolean successful = FALSE;

    url = g_strdup_printf ("%s/distributions.xml", rcd_prefs_get_host ());
    t = rcd_transfer_new (url, 0, rcd_cache_get_normal_cache ());
    g_free (url);

    data = rcd_transfer_begin_blocking (t);

    if (rcd_transfer_get_error (t)) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Unable to download supported distribution info; "
                  "falling back: %s", rcd_transfer_get_error_string (t));
        goto cleanup;
    }

    if (!rc_distro_parse_xml (data->data, data->len)) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Unable to parse supported distribution info; "
                  "falling back");
        goto cleanup;
    }
    else
        successful = TRUE;

cleanup:
    g_object_unref (t);

    if (data)
        g_byte_array_free (data, TRUE);

    /* Fall back onto compiled in distro info. */
    if (!successful) {
        if (rc_distro_parse_xml (NULL, 0))
            return TRUE;
        else
            return FALSE;
    }
    else
        return TRUE;
} /* rcd_fetch_distro */

static void
write_file_contents (const char *filename, GByteArray *data)
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

static char *
get_channel_list_url (void)
{
    char *url = NULL;

    if (rcd_prefs_get_premium ()) {
        url = g_strdup_printf ("%s/channels.php?distro_target=%s",
                               rcd_prefs_get_host (),
                               rc_distro_get_target ());
    } else {
        url = g_strdup_printf ("%s/channels.xml.gz",
                               rcd_prefs_get_host ());
    }

    return url;
} /* get_channel_list_url */

static void
remove_channel_cb (RCChannel *channel, gpointer user_data)
{
    if (! rc_channel_has_refresh_magic (channel)) {
        rc_world_remove_channel (rc_get_world (), channel);
    }
} /* remove_channel_cb */

gboolean
rcd_fetch_channel_list (void)
{
    RCDTransfer *t;
    gchar *url = NULL;
    GByteArray *data = NULL;
    xmlDoc *doc = NULL;
    xmlNode *root;
    gboolean success = FALSE;

    url = get_channel_list_url ();

    t = rcd_transfer_new (url, 0, rcd_cache_get_normal_cache ());
    data = rcd_transfer_begin_blocking (t);

    if (rcd_transfer_get_error (t)) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Attempt to download the channel list failed: %s",
                  rcd_transfer_get_error_string (t));
        goto cleanup;
    }

    doc = rc_uncompress_xml (data->data, data->len);
    if (doc == NULL) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Unable to uncompress or parse channel list.");
        goto cleanup;
    }

    root = xmlDocGetRootElement (doc);
    if (root == NULL) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Channel list is empty.");
        goto cleanup;
    }

    rc_world_foreach_channel (rc_get_world (), remove_channel_cb, NULL);
    rc_world_add_channels_from_xml (rc_get_world (), root->xmlChildrenNode);
    write_file_contents ("/var/lib/rcd/channels.xml.gz", data);

    success = TRUE;

 cleanup:

    if (url)
        g_free (url);
    
    if (t)
        g_object_unref (t);
    
    if (data)
        g_byte_array_free (data, TRUE);
    
    if (doc)
        xmlFreeDoc (doc);

    return success;
}

gboolean
rcd_fetch_channel_list_local (void)
{
    gchar *url = NULL;
    gchar *local_file = NULL;
    RCBuffer *buf = NULL;
    xmlDoc *doc = NULL;
    xmlNode *root;
    gboolean success = FALSE;

    local_file = "/var/lib/rcd/channels.xml.gz";

    if (!g_file_test (local_file, G_FILE_TEST_EXISTS))
        goto cleanup;
        
    buf = rc_buffer_map_file (local_file);

    if (!buf)
        goto cleanup;

    doc = rc_uncompress_xml (buf->data, buf->size);

    if (!doc)
        goto cleanup;

    root = xmlDocGetRootElement (doc);
    if (!root)
        goto cleanup;

    rc_world_foreach_channel (rc_get_world (), remove_channel_cb, NULL);
    rc_world_add_channels_from_xml (rc_get_world (), root->xmlChildrenNode);

    success = TRUE;

 cleanup:

    if (url)
        g_free (url);

    if (buf)
        rc_buffer_unmap_file (buf);
    
    if (doc)
        xmlFreeDoc (doc);

    return success;
}    

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

typedef struct {
    GByteArray *data;
    RCChannel  *channel;
} ChannelFetchClosure;

static void
channel_data_cb (RCDTransfer *t, char *buf, gsize size, gpointer user_data)
{
    ChannelFetchClosure *closure = user_data;

    closure->data = g_byte_array_append (closure->data, buf, size);
} /* channel_data_cb */

static void
process_channel_cb (RCDTransfer *t, gpointer user_data)
{
    ChannelFetchClosure *closure = user_data;
    GByteArray *data = closure->data;
    RCChannel *channel = closure->channel;
    char *local_file;
    gboolean success;

    g_assert (data != NULL);

    if (rcd_transfer_get_error (t)) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Unable to download %s: %s", t->url,
                  rcd_transfer_get_error_string (t));
    }
    
    data = g_byte_array_append (data, "\0", 1);

    /* Clear any old channel info out of the world. */
    rc_world_remove_packages (rc_get_world (), channel);

    if (rc_channel_get_pkginfo_compressed (channel)) {
        
        success = rc_world_add_packages_from_buffer (rc_get_world (),
                                                     channel,
                                                     data->data,
                                                     data->len);
    } else {
        
        success = rc_world_add_packages_from_buffer (rc_get_world (),
                                                     channel,
                                                     data->data,
                                                     0);

    }

    /* 
     *  We try to ensure that these files are always the last
     * known good files.
     */
    if (success) {
        local_file = g_strdup_printf ("/var/lib/rcd/channel-%d.xml%s",
                                      rc_channel_get_id (channel),
                                      rc_channel_get_pkginfo_compressed (channel) ? ".gz" : "");
        write_file_contents (local_file, data);
        g_free (local_file);

        rc_debug (RC_DEBUG_LEVEL_INFO,
                  "Loaded channel '%s'",
                  rc_channel_get_name (channel));
    } else {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Attempt to load package data for channel '%s' failed",
                  rc_channel_get_name (channel));
    }

    g_byte_array_free (data, TRUE);

    rc_channel_unref (closure->channel);
    g_free (closure);

    g_object_unref (t);
}

gint
rcd_fetch_channel (RCChannel *channel)
{
    RCDTransfer *t;
    ChannelFetchClosure *closure;
    gchar *url, *desc;
    RCDPending *pending;

    g_return_val_if_fail (channel != NULL, RCD_INVALID_PENDING_ID);

    if (rc_channel_has_refresh_magic (channel)) {
        rc_channel_use_refresh_magic (channel);
        return RCD_INVALID_PENDING_ID;
    }

    url = merge_paths (rcd_prefs_get_host (),
                       rc_channel_get_pkginfo_file (channel));

    t = rcd_transfer_new (url, 0, rcd_cache_get_normal_cache ());
    g_free (url);

    closure = g_new0 (ChannelFetchClosure, 1);
    closure->data = g_byte_array_new ();
    closure->channel = rc_channel_ref (channel);

    g_signal_connect (t,
                      "file_data",
                      (GCallback) channel_data_cb,
                      closure);
    g_signal_connect (t,
                      "file_done",
                      (GCallback) process_channel_cb,
                      closure);

    rcd_transfer_begin (t);

    if (rcd_transfer_get_error (t)) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Attempt to download channel data for '%s' (%d) failed: %s",
                  rc_channel_get_name (channel), rc_channel_get_id (channel),
                  rcd_transfer_get_error_string (t));

        rc_channel_unref (closure->channel);
        g_byte_array_free (closure->data, FALSE);
        g_free (closure);

        return RCD_INVALID_PENDING_ID;
    }

    /* Attach a more meaningful description to our pending object. */
    pending = rcd_transfer_get_pending (t);
    desc = g_strdup_printf ("Download '%s' channel info",
                            rc_channel_get_name (channel));
    rcd_pending_set_description (pending, desc);
    g_free (desc);
    
    return rcd_pending_get_id (pending);
}

gboolean
rcd_fetch_channel_local (RCChannel *channel)
{
    char *local_file;
    RCBuffer *buf;

    g_return_val_if_fail (channel != NULL, FALSE);

    if (rc_channel_has_refresh_magic (channel)) {
        rc_channel_use_refresh_magic (channel);
        return TRUE;
    }

    local_file = g_strdup_printf (
        "/var/lib/rcd/channel-%d.xml%s",
        rc_channel_get_id (channel),
        rc_channel_get_pkginfo_compressed (channel) ? ".gz" : "");

    if (!g_file_test (local_file, G_FILE_TEST_EXISTS)) {
        g_free (local_file);
        return FALSE;
    }

    buf = rc_buffer_map_file (local_file);
    g_free (local_file);

    if (!buf)
        return FALSE;

    /* Clear any old channel info out of the world. */
    rc_world_remove_packages (rc_get_world (), channel);

    if (rc_channel_get_pkginfo_compressed (channel)) {

        rc_world_add_packages_from_buffer (rc_get_world (),
                                           channel,
                                           buf->data,
                                           buf->size);
    } else {

        rc_world_add_packages_from_buffer (rc_get_world (),
                                           channel,
                                           buf->data,
                                           0);
    }

    rc_debug (RC_DEBUG_LEVEL_INFO,
              "Loaded channel '%s'",
              rc_channel_get_name (channel));

    rc_buffer_unmap_file (buf);

    return TRUE;
}

static void
process_icon_cb (RCDTransfer *t, gpointer user_data)
{
    RCChannel *channel = user_data;

    rc_channel_unref (channel);
} /* process_icon_cb */

int
rcd_fetch_channel_icon (RCChannel *channel)
{
    RCDTransfer *t;
    char *url, *desc;
    RCDPending *pending;

    g_return_val_if_fail (channel != NULL, RCD_INVALID_PENDING_ID);

    url = merge_paths (rcd_prefs_get_host (),
                       rc_channel_get_icon_file (channel));

    t = rcd_transfer_new (
        url, 0, rcd_cache_get_icon_cache (rc_channel_get_id (channel)));

    g_free (url);

    rc_channel_ref (channel);

    g_signal_connect (t, "file_done", G_CALLBACK (process_icon_cb), channel);

    rcd_transfer_begin (t);

    if (rcd_transfer_get_error (t)) {
        rc_debug (RC_DEBUG_LEVEL_ERROR,
                  "Attempt to download channel icon for '%s' (%d) failed: %s",
                  rc_channel_get_name (channel), rc_channel_get_id (channel),
                  rcd_transfer_get_error_string (t));
        rc_channel_unref (channel);
        return RCD_INVALID_PENDING_ID;
    }

    /* Attach a more meaningful description to our pending object. */
    pending = rcd_transfer_get_pending (t);
    desc = g_strdup_printf ("Downloading '%s' channel icon",
                            rc_channel_get_name (channel));
    rcd_pending_set_description (pending, desc);
    g_free (desc);

    return rcd_pending_get_id (pending);
} /* rcd_fetch_channel_icon */

static void
fetch_icon_cb (RCChannel *channel, gpointer user_data)
{
    gboolean refetch = GPOINTER_TO_INT (user_data);

    if (!refetch) {
        char *local_file;
        gboolean have_icon;

        local_file = rcd_cache_get_local_filename (
            rcd_cache_get_icon_cache (rc_channel_get_id (channel)),
            rc_channel_get_icon_file (channel));

        have_icon = g_file_test (local_file, G_FILE_TEST_EXISTS);

        g_free (local_file);

        /* We have the icon, don't bother to fetch it. */
        if (have_icon)
            return;
    }

    rcd_fetch_channel_icon (channel);
} /* fetch_icon_cb */

void
rcd_fetch_all_channel_icons (gboolean refetch)
{
    rc_world_foreach_channel (rc_get_world (), fetch_icon_cb,
                              GINT_TO_POINTER (refetch));
} /* rcd_fetch_all_channel_icons */

struct FetchAllInfo {
    GSList *id_list;
    RCDFetchChannelFlags flags;
};

static void
all_channels_cb (RCChannel *channel, gpointer user_data)
{
    struct FetchAllInfo *info = user_data;
    int id;
    RCDFetchChannelFlags ch_flags = 0;
    
    if (rc_channel_get_transient (channel)) {
        ch_flags |= RCD_FETCH_TRANSIENT;
    } else {
        ch_flags |= RCD_FETCH_PERSISTENT;
    }

    if (! (info->flags & ch_flags))
        return;

    if (info->flags & RCD_FETCH_LOCAL) {
        if (!rcd_fetch_channel_local (channel)) {
            id = rcd_fetch_channel (channel);
            if (id != RCD_INVALID_PENDING_ID)
                info->id_list = g_slist_prepend (info->id_list,
                                                 GINT_TO_POINTER (id));
        }
    }
    else {
        id = rcd_fetch_channel (channel);
        if (id != RCD_INVALID_PENDING_ID)
            info->id_list = g_slist_prepend (info->id_list,
                                             GINT_TO_POINTER (id));
    }
}

GSList *
rcd_fetch_all_channels (void)
{
    GSList *ids;
    
    ids = rcd_fetch_some_channels (RCD_FETCH_TRANSIENT |
                                   RCD_FETCH_PERSISTENT);
    return ids;
}

void
rcd_fetch_all_channels_local (void)
{
    GSList *ids;
    
    ids = rcd_fetch_some_channels (RCD_FETCH_LOCAL |
                                   RCD_FETCH_TRANSIENT |
                                   RCD_FETCH_PERSISTENT);

    /* ids should just be NULL, but we free it just in case. */
    g_slist_free (ids);
}

GSList *
rcd_fetch_some_channels (RCDFetchChannelFlags flags)
{
    struct FetchAllInfo info;

    info.id_list = NULL;
    info.flags = flags;

    rc_world_foreach_channel (rc_get_world (),
                              all_channels_cb,
                              &info);

    return info.id_list;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static gchar *
get_news_url (void)
{
    return g_strdup_printf ("%s/red-carpet.rdf",
                            rcd_prefs_get_host ());
}

static void
parse_news_xml (xmlDoc *doc)
{
    xmlNode *node;

    g_return_if_fail (doc != NULL);

    node = xmlDocGetRootElement (doc);
    g_return_if_fail (node != NULL);

    node = node->xmlChildrenNode;
    while (node != NULL) {
        if (! g_strcasecmp (node->name, "item")) {
            RCDNews *news = rcd_news_parse (node);
            rcd_news_add (news);
        }
        node = node->next;
    }
}

void
rcd_fetch_news (void)
{
    RCDTransfer *t;
    gchar *url = NULL;
    GByteArray *data = NULL;
    xmlDoc *doc = NULL;

    url = get_news_url ();

    t = rcd_transfer_new (url, 0, rcd_cache_get_normal_cache ());
    data = rcd_transfer_begin_blocking (t);

    g_assert (data);

    if (rcd_transfer_get_error (t)) {

        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Attempt to download news failed: %s",
                  rcd_transfer_get_error_string (t));
        
        goto cleanup;
    }

    {
        /* FIXME!  A silly hack to get around the fact that the
           current RDF file isn't valid utf-8 */

        int i;
        for (i = 0; i < data->len; ++i) {
            if (data->data[i] >= 0x80)
                data->data[i] = '_';
        }
    }

    doc = xmlParseMemory (data->data, data->len);
    if (doc == NULL) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Couldn't parse news XML file.");
        goto cleanup;
    }

    rcd_news_clear ();
    parse_news_xml (doc);
    write_file_contents ("/var/lib/rcd/news.rdf", data);

 cleanup:

    if (url)
        g_free (url);
    
    if (t)
        g_object_unref (t);

    if (data)
        g_byte_array_free (data, TRUE);

    if (doc)
        xmlFreeDoc (doc);
}

gboolean
rcd_fetch_news_local (void)
{
    gchar *local_file;
    RCBuffer *buf;
    xmlDoc *doc;

    local_file = "/var/lib/rcd/news.rdf";

    if (! g_file_test (local_file, G_FILE_TEST_EXISTS))
        return FALSE;
    
    buf = rc_buffer_map_file (local_file);

    if (! buf)
        return FALSE;

    doc = xmlParseMemory (buf->data, buf->size);
    
    rc_buffer_unmap_file (buf);

    if (! doc)
        return FALSE;

    rcd_news_clear ();
    parse_news_xml (doc);

    xmlFreeDoc (doc);

    return TRUE;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static gchar *
get_mirrors_url (void)
{
    return g_strdup ("http://red-carpet.ximian.com/mirrors.xml"); /* FIXME */
}

static void
parse_mirrors_xml (xmlDoc *doc)
{
    xmlNode *node;

    g_return_if_fail (doc != NULL);

    node = xmlDocGetRootElement (doc);
    g_return_if_fail (node != NULL);

    node = node->xmlChildrenNode;
    while (node != NULL) {
        if (! g_strcasecmp (node->name, "mirror")) {
            RCDMirror *mirror = rcd_mirror_parse (node);
            if (mirror)
                rcd_mirror_add (mirror);
        }
        node = node->next;
    }
}

void
rcd_fetch_mirrors (void)
{
    RCDTransfer *t;
    gchar *url = NULL;
    GByteArray *data = NULL;
    xmlDoc *doc = NULL;

    url = get_mirrors_url ();
    t = rcd_transfer_new (url, 0, rcd_cache_get_normal_cache ());
    data = rcd_transfer_begin_blocking (t);

    g_assert (data);

    if (rcd_transfer_get_error (t)) {
        
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Attempt to download mirror list failed: %s",
                  rcd_transfer_get_error_string (t));
        goto cleanup;
    }

    doc = xmlParseMemory (data->data, data->len);
    if (doc == NULL) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Couldn't parse mirrors XML file.");
        goto cleanup;
    }

    rcd_mirror_clear ();
    parse_mirrors_xml (doc);
    write_file_contents ("/var/lib/rcd/mirrors.xml", data);
    
 cleanup:

    if (url)
        g_free (url);

    if (t)
        g_object_unref (t);

    if (data)
        g_byte_array_free (data, TRUE);

    if (doc)
        xmlFreeDoc (doc);
}

gboolean
rcd_fetch_mirrors_local (void)
{
    gchar *local_file;
    RCBuffer *buf;
    xmlDoc *doc;

    local_file = "/var/lib/rcd/mirrors.xml";

    if (! g_file_test (local_file, G_FILE_TEST_EXISTS))
        return FALSE;

    buf = rc_buffer_map_file (local_file);

    if (! buf)
        return FALSE;

    doc = xmlParseMemory (buf->data, buf->size);

    rc_buffer_unmap_file (buf);

    if (! doc)
        return FALSE;

    rcd_mirror_clear ();
    parse_mirrors_xml (doc);

    xmlFreeDoc (doc);
    
    return TRUE;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static GHashTable *package_transfer_table = NULL;

typedef struct {
    int transfer_id;
    int refs;

    GSList *running_transfers;
    GSList *queued_transfers;

    RCDFetchProgressFunc  progress_callback;
    RCDFetchCompletedFunc completed_callback;
    gpointer user_data;

    gboolean successful;
    char *error_message;
} PackageFetchClosure;

static void
begin_package_download (RCDTransfer *t, PackageFetchClosure *closure)
{
    rc_debug (RC_DEBUG_LEVEL_INFO, "Beginning download of package %s", t->url);

    closure->running_transfers = g_slist_append (
        closure->running_transfers, t);

    rcd_transfer_begin (t);

    if (!rcd_transfer_get_error (t)) {
        RCDPending *pending;
        char *desc;

        /* Attach a more meaningful description to our pending object. */
        pending = rcd_transfer_get_pending (t);
        desc = g_strdup_printf ("Downloading package %s", t->url);
        rcd_pending_set_description (pending, desc);
        g_free (desc);
    }
    else {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Attenpt to download package failed: %s",
                  rcd_transfer_get_error_string (t));

        closure->successful = FALSE;
        closure->error_message = g_strdup (rcd_transfer_get_error_string (t));

        rcd_fetch_packages_abort (closure->transfer_id);
    }
} /* begin_package_download */

static void
begin_queued_package_download (PackageFetchClosure *closure)
{
    RCDTransfer *t;

    if (!closure->queued_transfers)
        return;

    t = (RCDTransfer *) closure->queued_transfers->data;

    closure->queued_transfers = g_slist_remove (closure->queued_transfers, t);

    begin_package_download (t, closure);
} /* begin_queued_package_download */

static void
queue_package_download (RCDTransfer *t, PackageFetchClosure *closure)
{
    rc_debug (RC_DEBUG_LEVEL_INFO, "Queuing up package %s", t->url);

    closure->queued_transfers = g_slist_append (closure->queued_transfers, t);
} /* queue_package_download */

static void
package_progress_cb (RCDTransfer *t,
                     char        *buffer,
                     gsize        size,
                     gpointer     user_data)
{
    PackageFetchClosure *closure = user_data;

    closure->progress_callback (size, closure->user_data);
} /* package_progress_cb */

static void
package_completed_cb (RCDTransfer *t, gpointer user_data)
{
    PackageFetchClosure *closure = user_data;
    RCPackage *package;

    closure->running_transfers = g_slist_remove (
        closure->running_transfers, t);

    if (rcd_transfer_get_error (t) == RCD_TRANSFER_ERROR_CANCELLED) {
        rc_debug (RC_DEBUG_LEVEL_INFO, "Download of %s cancelled", t->url);

        if (!closure->running_transfers) {
            closure->completed_callback (
                FALSE, closure->error_message, closure->user_data);
            g_free (closure->error_message);
        }
    }
    else if (rcd_transfer_get_error (t)) {
        rc_debug (RC_DEBUG_LEVEL_INFO, "Download of %s failed", t->url);

        if (closure->running_transfers) {
            closure->successful = FALSE;
            closure->error_message = g_strdup (
                rcd_transfer_get_error_string (t));

            rcd_fetch_packages_abort (closure->transfer_id);
        }
        else {
            closure->completed_callback (
                FALSE, rcd_transfer_get_error_string (t), closure->user_data);
        }
    }
    else {
        rc_debug (RC_DEBUG_LEVEL_INFO, "Download of %s complete", t->url);
    
        package = g_object_get_data (G_OBJECT (t), "package");
        if (g_object_get_data (G_OBJECT (t), "is_signature"))
            package->signature_filename = rcd_transfer_get_local_filename (t);
        else
            package->package_filename = rcd_transfer_get_local_filename (t);

        /* Fire off a queued transfer if there are any */
        begin_queued_package_download (closure);

        if (!closure->running_transfers) {
            rc_debug (RC_DEBUG_LEVEL_INFO,
                      "No more pending transfers, calling callback");

            if (closure->successful)
                closure->completed_callback (TRUE, NULL, closure->user_data);
            else {
                closure->completed_callback (
                    FALSE, closure->error_message, closure->user_data);
                g_free (closure->error_message);
            }
        }
    }

    if (!closure->running_transfers && !closure->queued_transfers) {
        g_hash_table_remove (package_transfer_table,
                             GINT_TO_POINTER (closure->transfer_id));
        g_free (closure);
    }

    g_object_unref (t);
} /* package_completed_cb */

static void
download_package_file (RCPackage           *package,
                       const char          *file_url,
                       PackageFetchClosure *closure,
                       gboolean             is_signature)
{
    RCDTransfer *t;
    char *url;
    int max_downloads;

    url = merge_paths (rcd_prefs_get_host (), file_url);

    t = rcd_transfer_new (
        url,
        RCD_TRANSFER_FLAGS_FORCE_CACHE |
        RCD_TRANSFER_FLAGS_RESUME_PARTIAL,
        rcd_cache_get_package_cache ());
    g_object_set_data (G_OBJECT (t), "package", package);

    if (is_signature)
        g_object_set_data (G_OBJECT (t), "is_signature", GINT_TO_POINTER (1));

    g_free (url);

    g_signal_connect (t,
                      "file_data",
                      (GCallback) package_progress_cb,
                      closure);

    g_signal_connect (t,
                      "file_done",
                      (GCallback) package_completed_cb,
                      closure);

    max_downloads = rcd_prefs_get_max_downloads ();

    if (max_downloads &&
        g_slist_length (closure->running_transfers) >= max_downloads)
        queue_package_download (t, closure);
    else
        begin_package_download (t, closure);
} /* download_package_file */

void
rcd_fetch_packages (RCPackageSList        *packages,
                    int                    pending_id,
                    RCDFetchProgressFunc   progress_callback,
                    RCDFetchCompletedFunc  completed_callback,
                    gpointer               user_data)
{
    PackageFetchClosure *closure;
    RCPackageSList *iter;

    g_return_if_fail (packages != NULL);

    closure = g_new0 (PackageFetchClosure, 1);
    closure->transfer_id = pending_id;
    closure->progress_callback = progress_callback;
    closure->completed_callback = completed_callback;
    closure->user_data = user_data;
    closure->successful = TRUE;

    if (!package_transfer_table)
        package_transfer_table = g_hash_table_new (NULL, NULL);

    g_hash_table_insert (package_transfer_table,
                         GINT_TO_POINTER (closure->transfer_id),
                         closure);
    
    for (iter = packages; iter; iter = iter->next) {
        RCPackage *package = iter->data;
        RCPackageUpdate *update = rc_package_get_latest_update (package);
        
        download_package_file (package, update->package_url, closure, FALSE);

        if (update->signature_url) {
            download_package_file (package, update->signature_url,
                                   closure, TRUE);
        }
    }
}

void
rcd_fetch_packages_abort (int transfer_id)
{
    PackageFetchClosure *closure;
    GSList *iter;
    GSList *next;

    closure = g_hash_table_lookup (package_transfer_table,
                                   GINT_TO_POINTER (transfer_id));

    g_return_if_fail (closure);

    for (iter = closure->queued_transfers; iter; iter = iter->next)
        g_object_unref (iter->data);

    for (iter = closure->running_transfers; iter; iter = next) {
        next = iter->next;

        rcd_transfer_abort (iter->data);
    }
} /* rcd_fetch_packages_abort */
