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

#include <libredcarpet.h>
#include "rcd-transfer.h"
#include "rcd-cache.h"
#include "rcd-news.h"
#include "rcd-prefs.h"

static char *
get_channel_list_url (void)
{
    RCDistroType *dt;
    char *url;

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

    if (rcd_prefs_get_priority ()) {
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

    if (data == NULL || rcd_transfer_get_error (t)) {
        /* FIXME: can we give more detail about the problem? */
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Attempt to download the channel list failed.");
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
    gchar *url;
    gchar *local_file;
    RCBuffer *buf;
    xmlDoc *doc;
    xmlNode *root;

    url = get_channel_list_url ();
    local_file = rcd_cache_get_local_filename (
        rcd_cache_get_normal_cache (), url);
    g_free (url);

    if (!g_file_test (local_file, G_FILE_TEST_EXISTS))
        return FALSE;
        
    buf = rc_buffer_map_file (local_file);
    g_free (local_file);

    if (!buf)
        return FALSE;

    doc = rc_uncompress_xml (buf->data, buf->size);

    rc_buffer_unmap_file (buf);

    if (!doc)
        return FALSE;

    root = xmlDocGetRootElement (doc);
    if (!root)
        return FALSE;

    rc_world_add_channels_from_xml (rc_get_world (), root->xmlChildrenNode);
    
    xmlFreeDoc (doc);

    return TRUE;
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

    g_assert (data != NULL); /* FIXME? */

    if (rcd_transfer_get_error (t)) {
        g_assert_not_reached (); /* FIXME */
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

    rc_debug (RC_DEBUG_LEVEL_INFO,
              "Loaded channel '%s'",
              rc_channel_get_name (channel));

    g_byte_array_free (data, TRUE);
    g_free (closure);
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

    /* FIXME: deal with mirrors */
    url = g_strdup_printf ("%s/%s",
                           rcd_prefs_get_host (),
                           rc_channel_get_pkginfo_file (channel));

    rcd_transfer_begin (t, url);
    g_free (url);

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
    char *url;
    char *local_file;
    RCBuffer *buf;

    g_return_val_if_fail (channel != NULL, FALSE);

    /* FIXME: deal with mirrors */
    url = g_strdup_printf ("%s/%s",
                           rcd_prefs_get_host (),
                           rc_channel_get_pkginfo_file (channel));
    local_file = rcd_cache_get_local_filename (
        rcd_cache_get_normal_cache (), url);
    g_free (url);

    if (!g_file_test (local_file, G_FILE_TEST_EXISTS))
        return FALSE;

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


    if (info->local)
        rcd_fetch_channel_local (channel);
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
    g_free (url);

    if (data == NULL || rcd_transfer_get_error (t)) {

        /* FIXME: we could be a bit more specific here. */
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Attempt to download news failed.");
        
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
    gchar *url, *local_file;
    RCBuffer *buf;
    xmlDoc *doc;

    url = get_news_url ();
    local_file = rcd_cache_get_local_filename (rcd_cache_get_normal_cache (),
                                               url);
    g_free (url);

    if (! g_file_test (local_file, G_FILE_TEST_EXISTS))
        return FALSE;
    
    buf = rc_buffer_map_file (local_file);
    g_free (local_file);

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

typedef struct {
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

    rc_debug (RC_DEBUG_LEVEL_INFO, "Download of %s complete", t->url);
    
    package = g_object_get_data (G_OBJECT (t), "package");
    package->package_filename = rcd_transfer_get_local_filename (t);

    closure->running_transfers = g_slist_remove (
        closure->running_transfers, t);

    if (!closure->running_transfers) {
        rc_debug (RC_DEBUG_LEVEL_INFO,
                  "No more pending transfers, calling callback");
        closure->completed_callback (closure->user_data);
        /* g_idle_add (closure->callback, closure->user_data); */
        g_free (closure);
    }
} /* process_package_cb */

void
rcd_fetch_packages (RCPackageSList       *packages,
                    RCDFetchProgressFunc  progress_callback,
                    GSourceFunc           completed_callback,
                    gpointer              user_data)
{
    PackageFetchClosure *closure;
    RCPackageSList *iter;

    g_return_if_fail (packages != NULL);

    closure = g_new0 (PackageFetchClosure, 1);
    closure->progress_callback = progress_callback;
    closure->completed_callback = completed_callback;
    closure->user_data = user_data;
    
    for (iter = packages; iter; iter = iter->next) {
        RCPackage *package = iter->data;
        RCPackageUpdate *update = rc_package_get_latest_update (package);
        RCDTransfer *t;
        char *url, *desc;
        RCDPending *pending;
        
        /* FIXME: We need to download signatures too */

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

        /* FIXME: deal with mirrors */
        url = g_strdup_printf ("%s/%s",
                               rcd_prefs_get_host (),
                               update->package_url);
        rcd_transfer_begin (t, url);

        /* Attach a more meaningful description to our pending object. */
        pending = rcd_transfer_get_pending (t);
        desc = g_strdup_printf ("Downloading package %s", url);
        rcd_pending_set_description (pending, desc);
        g_free (desc);
        g_free (url);
    }
}
