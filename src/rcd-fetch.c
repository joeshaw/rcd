/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-fetch.c
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
#include "rcd-fetch.h"

#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>

#include <libredcarpet.h>
#include "rcd-transfer.h"
#include "rcd-cache.h"
#include "rcd-news.h"
#include "rcd-prefs.h"

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
    RCDistroType *dt;
    char *url = NULL;

    dt = rc_figure_distro ();

    if (dt == NULL) {

        rc_debug (RC_DEBUG_LEVEL_ERROR,
                  "Unable to determine which distribution this system is running.  Aborting.");

        /* FIXME: Can we just exit, or do we need to do any clean-up? */
        exit (-1);
    }

    if (dt->pretend_name) {
        rc_debug (RC_DEBUG_LEVEL_INFO, "Distro pretends to be %s", dt->pretend_name);
    } else {
        rc_debug (RC_DEBUG_LEVEL_INFO, "Distro is %s", dt->unique_name);
    }

    if (rcd_prefs_get_premium ()) {
        url = g_strdup_printf ("%s/channels.php?distro_target=%s",
                               rcd_prefs_get_host (),
                               dt->pretend_name ? dt->pretend_name : dt->unique_name);
    } else {
        url = g_strdup_printf ("%s/channels.xml.gz",
                               rcd_prefs_get_host ());
    }

    return url;
} /* get_channel_list_url */

void
rcd_fetch_channel_list (void)
{
    RCDTransfer *t;
    gchar *url = NULL;
    GByteArray *data = NULL;
    xmlDoc *doc = NULL;
    xmlNode *root;

    url = get_channel_list_url ();

    t = rcd_transfer_new (0, rcd_cache_get_normal_cache ());
    data = rcd_transfer_begin_blocking (t, url);

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

    rc_world_add_channels_from_xml (rc_get_world (), root->xmlChildrenNode);
    write_file_contents ("/var/lib/rcd/channels.xml.gz", data);

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
        
        rc_world_add_packages_from_buffer (rc_get_world (),
                                           channel,
                                           data->data,
                                           data->len);
    } else {
        
        rc_world_add_packages_from_buffer (rc_get_world (),
                                           channel,
                                           data->data,
                                           0);

    }

    /* 
     * FIXME: The above add_packages functions should return success
     * or failure, and we should only write out the following on
     * success.  We should ensure that these files are always the last
     * known good files.
     */
    local_file = g_strdup_printf (
        "/var/lib/rcd/channel-%d.xml%s",
        rc_channel_get_id (channel),
        rc_channel_get_pkginfo_compressed (channel) ? ".gz" : "");
    write_file_contents (local_file, data);
    g_free (local_file);

    rc_debug (RC_DEBUG_LEVEL_INFO,
              "Loaded channel '%s'",
              rc_channel_get_name (channel));

    g_byte_array_free (data, TRUE);
    g_free (closure);
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


gint
rcd_fetch_channel (RCChannel *channel)
{
    RCDTransfer *t;
    ChannelFetchClosure *closure;
    gchar *url, *desc;
    RCDPending *pending;

    g_return_val_if_fail (channel != NULL, RCD_INVALID_PENDING_ID);

    t = rcd_transfer_new (0, rcd_cache_get_normal_cache ());

    closure = g_new0 (ChannelFetchClosure, 1);
    closure->data = g_byte_array_new ();
    closure->channel = channel;

    g_signal_connect (t,
                      "file_data",
                      (GCallback) channel_data_cb,
                      closure);
    g_signal_connect (t,
                      "file_done",
                      (GCallback) process_channel_cb,
                      closure);

    url = merge_paths (rcd_prefs_get_host (),
                       rc_channel_get_pkginfo_file (channel));

    rcd_transfer_begin (t, url);
    g_free (url);

    if (rcd_transfer_get_error (t)) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Attempt to download channel data for '%s' (%d) failed: %s",
                  rc_channel_get_name (channel), rc_channel_get_id (channel),
                  rcd_transfer_get_error_string (t));
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

struct FetchAllInfo {
    gboolean local;
    GSList *id_list;
};

static void
all_channels_cb (RCChannel *channel, gpointer user_data)
{
    struct FetchAllInfo *info = user_data;

    if (info->local) {
        if (!rcd_fetch_channel_local (channel))
            rcd_fetch_channel (channel);
    }
    else {
        gint id = rcd_fetch_channel (channel);
        if (id != RCD_INVALID_PENDING_ID)
            info->id_list = g_slist_prepend (info->id_list,
                                             GINT_TO_POINTER (id));
    }
}

GSList *
rcd_fetch_all_channels (void)
{
    struct FetchAllInfo info;

    info.local = FALSE;
    info.id_list = NULL;
    
    rc_world_foreach_channel (rc_get_world (),
                              all_channels_cb,
                              &info);

    return info.id_list;
}

void
rcd_fetch_all_channels_local (void)
{
    struct FetchAllInfo info;
    
    info.local = TRUE;
    info.id_list = NULL;

    rc_world_foreach_channel (rc_get_world (),
                              all_channels_cb,
                              &info);
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

    t = rcd_transfer_new (0, rcd_cache_get_normal_cache ());
    data = rcd_transfer_begin_blocking (t, url);

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

    parse_news_xml (doc);

    xmlFreeDoc (doc);

    return TRUE;
}

static GHashTable *package_transfer_table = NULL;
static int package_transfer_id = 0;

typedef struct {
    int transfer_id;

    GSList *running_transfers;

    RCDFetchProgressFunc progress_callback;
    GSourceFunc completed_callback;
    gpointer user_data;
} PackageFetchClosure;

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
    }
    else {
        rc_debug (RC_DEBUG_LEVEL_INFO, "Download of %s complete", t->url);
    
        package = g_object_get_data (G_OBJECT (t), "package");
        package->package_filename = rcd_transfer_get_local_filename (t);

        if (!closure->running_transfers) {
            rc_debug (RC_DEBUG_LEVEL_INFO,
                      "No more pending transfers, calling callback");
            closure->completed_callback (closure->user_data);
            /* g_idle_add (closure->callback, closure->user_data); */
        }
    }

    if (!closure->running_transfers) {
        g_hash_table_remove (package_transfer_table,
                             GINT_TO_POINTER (closure->transfer_id));
        g_free (closure);
    }
} /* process_package_cb */

static void
download_package_file (RCPackage           *package,
                       const char          *file_url,
                       PackageFetchClosure *closure)
{
    RCDTransfer *t;
    char *url, *desc;
    RCDPending *pending;

    t = rcd_transfer_new (
        RCD_TRANSFER_FLAGS_FORCE_CACHE |
        RCD_TRANSFER_FLAGS_RESUME_PARTIAL,
        rcd_cache_get_package_cache ());
    g_object_set_data (G_OBJECT (t), "package", package);

    closure->running_transfers = g_slist_append (
        closure->running_transfers, t);

    g_signal_connect (t,
                      "file_data",
                      (GCallback) package_progress_cb,
                      closure);

    g_signal_connect (t,
                      "file_done",
                      (GCallback) package_completed_cb,
                      closure);

    url = merge_paths (rcd_prefs_get_host (), file_url);
    rcd_transfer_begin (t, url);

    if (rcd_transfer_get_error (t)) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Attempt to download package failed: %s",
                  rcd_transfer_get_error_string (t));
        return;
    }

    /* Attach a more meaningful description to our pending object. */
    pending = rcd_transfer_get_pending (t);
    desc = g_strdup_printf ("Downloading package %s", url);
    rcd_pending_set_description (pending, desc);
    g_free (desc);
    g_free (url);
} /* download_package_file */

int
rcd_fetch_packages (RCPackageSList       *packages,
                    RCDFetchProgressFunc  progress_callback,
                    GSourceFunc           completed_callback,
                    gpointer              user_data)
{
    PackageFetchClosure *closure;
    RCPackageSList *iter;

    g_return_val_if_fail (packages != NULL, 0);

    closure = g_new0 (PackageFetchClosure, 1);
    closure->transfer_id = ++package_transfer_id;
    closure->progress_callback = progress_callback;
    closure->completed_callback = completed_callback;
    closure->user_data = user_data;

    if (!package_transfer_table)
        package_transfer_table = g_hash_table_new (NULL, NULL);

    g_hash_table_insert (package_transfer_table,
                         GINT_TO_POINTER (closure->transfer_id),
                         closure);
    
    for (iter = packages; iter; iter = iter->next) {
        RCPackage *package = iter->data;
        RCPackageUpdate *update = rc_package_get_latest_update (package);
        
        download_package_file (package, update->package_url, closure);

        if (update->signature_url)
            download_package_file (package, update->signature_url, closure);
    }

    return closure->transfer_id;
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

    for (iter = closure->running_transfers; iter; iter = next) {
        next = iter->next;

        rcd_transfer_abort (iter->data);
    }
} /* rcd_fetch_packages_abort */
