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
#include "rcd-prefs.h"

void
rcd_fetch_channel_list (void)
{
    RCDistroType *dt;
    RCDTransfer *t;
    gchar *url;
    GByteArray *data = NULL;
    xmlDoc *doc;
    xmlNode *root;

    dt = rc_figure_distro ();
    g_assert (dt != NULL); /* FIXME */

    if (dt->pretend_name) {
        rc_debug (RC_DEBUG_LEVEL_INFO, "Distro pretends to be %s", dt->pretend_name);
    } else {
        rc_debug (RC_DEBUG_LEVEL_INFO, "Distro is %s", dt->unique_name);
    }

    t = rcd_transfer_new (0, rcd_cache_get_normal_cache ());

    if (rcd_prefs_get_priority ()) {
        url = g_strdup_printf ("%s/channels.php?distro_target=%s",
                               rcd_prefs_get_host (),
                               dt->pretend_name ? dt->pretend_name : dt->unique_name);
    } else {
        url = g_strdup_printf ("%s/channels.xml.gz",
                               rcd_prefs_get_host ());
    }

    data = rcd_transfer_begin_blocking (t, url);
    g_free (url);

    g_assert (data != NULL); /* FIXME */

    if (rcd_transfer_get_error (t)) {
        g_assert_not_reached (); /* FIXME */
    }

    g_object_unref (t);

    doc = rc_uncompress_xml (data->data, data->len);
    g_byte_array_free (data, TRUE);
    g_assert (doc != NULL); /* FIXME */

    root = xmlDocGetRootElement (doc);
    g_assert (root != NULL); /* FIXME */

    rc_world_add_channels_from_xml (rc_get_world (), root->xmlChildrenNode);
    
    xmlFreeDoc (doc);
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

static void
all_channels_cb (RCChannel *channel, gpointer user_data)
{
    rcd_fetch_channel (channel);
}

void
rcd_fetch_all_channels (void)
{
    rc_world_foreach_channel (rc_get_world (),
                              all_channels_cb,
                              NULL);
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
