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

    t = rcd_transfer_new (RCD_TRANSFER_FLAGS_BLOCK,
                          rcd_cache_get_normal_cache ());

    if (rcd_prefs_get_priority ()) {
        url = g_strdup_printf ("%s/channels.php?distro_target=%s",
                               rcd_prefs_get_host (),
                               dt->pretend_name ? dt->pretend_name : dt->unique_name);
    } else {
        url = g_strdup_printf ("%s/channels.xml.gz",
                               rcd_prefs_get_host ());
    }

    data = rcd_transfer_begin (t, url);
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
}

void
rcd_fetch_channel (RCChannel *channel)
{
    RCDTransfer *t;
    gchar *url;
    GByteArray *data;
    gint count;
    xmlDoc *doc;
    xmlNode *node;

    g_return_if_fail (channel != NULL);

    t = rcd_transfer_new (RCD_TRANSFER_FLAGS_BLOCK,
                          rcd_cache_get_normal_cache ());

    /* FIXME: deal with mirrors */
    url = g_strdup_printf ("%s/%s",
                           rcd_prefs_get_host (),
                           rc_channel_get_pkginfo_file (channel));
    data = rcd_transfer_begin (t, url);
    g_free (url);

    g_assert (data != NULL); /* FIXME? */

    if (rcd_transfer_get_error (t)) {
        g_assert_not_reached (); /* FIXME */
    }

    g_object_unref (t);

    data = g_byte_array_append (data, "\0", 1);

    if (rc_channel_get_pkginfo_compressed (channel)) {
        
        doc = rc_uncompress_xml (data->data, data->len);

    } else {
        
        doc = xmlParseMemory (data->data, strlen (data->data));

    }
    g_byte_array_free (data, TRUE);
    node = xmlDocGetRootElement (doc);

    /* Clear any old channel info out of the world. */
    rc_world_remove_packages (rc_get_world (), channel);

    count = rc_world_add_packages_from_xml (rc_get_world (),
                                            channel,
                                            node);

    rc_debug (RC_DEBUG_LEVEL_INFO,
              "Got %d packages from '%s'",
              count, rc_channel_get_name (channel));
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
