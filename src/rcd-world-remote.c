/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-world-remote.c
 *
 * Copyright (C) 2003 Ximian, Inc.
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
#include "rcd-world-remote.h"

#include <sys/types.h>
#include <unistd.h>

#include <libredcarpet.h>

#include "rcd-license.h"
#include "rcd-news.h"
#include "rcd-transfer-pool.h"

#define RCD_WORLD_REMOTE_FETCH_FAILED ((gpointer) 0xdeadbeef)

static RCWorldServiceClass *parent_class;

static RCPending *rcd_world_remote_fetch (RCDWorldRemote *remote,
                                          gboolean        local);

static void
rcd_world_remote_finalize (GObject *obj)
{
    RCDWorldRemote *remote = RCD_WORLD_REMOTE (obj);

    g_free (remote->contact_email);
    g_free (remote->distributions_file);
    g_free (remote->mirrors_file);
    g_free (remote->licenses_file);
    g_free (remote->news_file);

    if (remote->distro)
        rc_distro_free (remote->distro);

    rcd_world_remote_clear_mirrors (remote);
    rcd_world_remote_clear_licenses (remote);
    rcd_world_remote_clear_news (remote);

    if (G_OBJECT_CLASS (parent_class)->finalize)
        G_OBJECT_CLASS (parent_class)->finalize (obj);
}

static RCPending *
rcd_world_remote_refresh (RCWorld *world)
{
    RCDWorldRemote *remote = RCD_WORLD_REMOTE (world);
    RCPending *pending;

    pending = rcd_world_remote_fetch (remote, FALSE);

    return pending;
}

static gboolean
rcd_world_remote_assemble (RCWorldService *service)
{
    RCPending *pending;

    pending = rcd_world_remote_fetch (RCD_WORLD_REMOTE (service), TRUE);

    if (pending == RCD_WORLD_REMOTE_FETCH_FAILED)
        return FALSE;

    return TRUE;
}

static void
rcd_world_remote_class_init (RCDWorldRemoteClass *klass)
{
    GObjectClass *object_class = (GObjectClass *) klass;
    RCWorldClass *world_class = (RCWorldClass *) klass;
    RCWorldServiceClass *service_class = (RCWorldServiceClass *) klass;

    parent_class = g_type_class_peek_parent (klass);

    object_class->finalize = rcd_world_remote_finalize;

    world_class->refresh_fn    = rcd_world_remote_refresh;

    service_class->assemble_fn = rcd_world_remote_assemble;
}

static void
rcd_world_remote_init (RCDWorldRemote *remote)
{

}

GType
rcd_world_remote_get_type (void)
{
    static GType type = 0;

    if (!type) {
        static GTypeInfo type_info = {
            sizeof (RCDWorldRemoteClass),
            NULL, NULL,
            (GClassInitFunc) rcd_world_remote_class_init,
            NULL, NULL,
            sizeof (RCDWorldRemote),
            0,
            (GInstanceInitFunc) rcd_world_remote_init
        };

        type = g_type_register_static (RC_TYPE_WORLD_SERVICE,
                                       "RCDWorldRemote",
                                       &type_info,
                                       0);
    }

    return type;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static char *
rcd_world_remote_get_channel_data_url (RCDWorldRemote *remote,
                                       RCChannel      *channel)
{
    return rc_maybe_merge_paths (RC_WORLD_SERVICE (remote)->url,
                                 rc_channel_get_pkginfo_file (channel));
}

static char *
rcd_world_remote_get_channel_icon_url (RCDWorldRemote *remote,
                                       RCChannel      *channel)
{
    return rc_maybe_merge_paths (RC_WORLD_SERVICE (remote)->url,
                                 rc_channel_get_icon_file (channel));
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static void
rcd_world_remote_fetch_distributions (RCDWorldRemote *remote)
{
    char *url;
    RCDCacheEntry *entry;
    RCDTransfer *t;
    const GByteArray *data;

    url = rc_maybe_merge_paths (RC_WORLD_SERVICE (remote)->url,
                                remote->distributions_file);
    entry = rcd_cache_lookup (rcd_cache_get_normal_cache (),
                              "distro_info",
                              RC_WORLD_SERVICE (remote)->unique_id,
                              TRUE);
    t = rcd_transfer_new (url, RCD_TRANSFER_FLAGS_NONE, entry);
    g_free (url);

    data = rcd_transfer_begin_blocking (t);

    if (rcd_transfer_get_error (t)) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Unable to downloaded distribution info: %s",
                  rcd_transfer_get_error_string (t));
        goto cleanup; /* FIXME? */
    }

    remote->distro = rc_distro_parse_xml (data->data, data->len);

    if (!remote->distro) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Unable to parse distribution info");
    }

cleanup:
    g_object_unref (t);
}

static void
rcd_world_remote_fetch_licenses (RCDWorldRemote *remote)
{
    char *url;
    RCDCacheEntry *entry;
    RCDTransfer *t;
    const GByteArray *data;

    url = rc_maybe_merge_paths (RC_WORLD_SERVICE (remote)->url,
                                remote->licenses_file);
    entry = rcd_cache_lookup (rcd_cache_get_normal_cache (),
                              "licenses", RC_WORLD_SERVICE (remote)->unique_id,
                              TRUE);
    t = rcd_transfer_new (url, RCD_TRANSFER_FLAGS_NONE, entry);
    g_free (url);

    data = rcd_transfer_begin_blocking (t);

    if (rcd_transfer_get_error (t)) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Unable to downloaded licenses info: %s",
                  rcd_transfer_get_error_string (t));
        goto cleanup;
    }

    if (!rcd_license_parse (remote, data->data, data->len))
        rc_debug (RC_DEBUG_LEVEL_CRITICAL, "Unable to parse licenses info");

cleanup:
    g_object_unref (t);
}

static void
rcd_world_remote_fetch_news (RCDWorldRemote *remote)
{
    char *url;
    RCDCacheEntry *entry;
    RCDTransfer *t;
    const GByteArray *data;
    xmlDoc *doc;
    xmlNode *node;

    url = rc_maybe_merge_paths (RC_WORLD_SERVICE (remote)->url,
                                remote->news_file);
    entry = rcd_cache_lookup (rcd_cache_get_normal_cache (),
                              "news", RC_WORLD_SERVICE (remote)->unique_id,
                              TRUE);
    t = rcd_transfer_new (url, RCD_TRANSFER_FLAGS_NONE, entry);
    g_free (url);

    data = rcd_transfer_begin_blocking (t);

    if (rcd_transfer_get_error (t)) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Unable to downloaded licenses info: %s",
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

    doc = rc_parse_xml_from_buffer (data->data, data->len);
    if (doc == NULL) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL, "Couldn't parse news XML file");
        goto cleanup;
    }

    rcd_world_remote_clear_news (remote);

    node = xmlDocGetRootElement (doc);

    for (node = node->xmlChildrenNode; node != NULL; node = node->next) {
        if (node->type == XML_COMMENT_NODE || node->type == XML_TEXT_NODE)
            continue;

        if (!g_strcasecmp (node->name, "item")) {
            RCDNews *news = rcd_news_parse (node);

            if (news)
                rcd_world_remote_add_news (remote, news);
        }
    }

    xmlFreeDoc (doc);

cleanup:
    g_object_unref (t);
}

static void
rcd_world_remote_fetch_mirrors (RCDWorldRemote *remote)
{
    RCDCacheEntry *entry;
    RCDTransfer *t;
    gchar *url = NULL;
    const GByteArray *data = NULL;
    xmlDoc *doc = NULL;
    xmlNode *node;

    url = rc_maybe_merge_paths (RC_WORLD_SERVICE (remote)->url,
                                remote->mirrors_file);
    entry = rcd_cache_lookup (rcd_cache_get_normal_cache (),
                              "mirrors", RC_WORLD_SERVICE (remote)->unique_id,
                              TRUE);
    t = rcd_transfer_new (url, 0, entry);
    g_free (url);

    data = rcd_transfer_begin_blocking (t);

    if (rcd_transfer_get_error (t)) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Attempt to download mirror list failed: %s",
                  rcd_transfer_get_error_string (t));
        goto cleanup;
    }

    doc = rc_parse_xml_from_buffer (data->data, data->len);
    if (doc == NULL) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL, "Couldn't parse mirrors XML file.");
        goto cleanup;
    }

    rcd_world_remote_clear_mirrors (remote);

    node = xmlDocGetRootElement (doc);

    for (node = node->xmlChildrenNode; node != NULL; node = node->next) {
        if (node->type == XML_COMMENT_NODE || node->type == XML_TEXT_NODE)
            continue;

        if (!g_strcasecmp (node->name, "mirror")) {
            RCDMirror *mirror = rcd_mirror_parse (node);

            if (mirror)
                rcd_world_remote_add_mirror (remote, mirror);
        }
    }

    xmlFreeDoc (doc);
    
 cleanup:
    g_object_unref (t);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static gboolean
load_package (RCPackage *package, gpointer user_data)
{
    RCWorldStore *store = RC_WORLD_STORE (user_data);

    rc_world_store_add_package (store, package);

    return TRUE;
}

static void
rcd_world_remote_parse_channel_data (RCDWorldRemote *remote,
                                     RCChannel      *channel,
                                     const guint8   *buffer,
                                     gint            buffer_len)
{
    GByteArray *decompressed_data = NULL;
    int count;

    if (rc_memory_looks_compressed (buffer, buffer_len)) {
        rc_uncompress_memory (buffer, buffer_len, &decompressed_data);
        buffer = decompressed_data->data;
        buffer_len = decompressed_data->len;
    }

    switch (rc_channel_get_type (channel)) {
    case RC_CHANNEL_TYPE_HELIX:
        count = rc_extract_packages_from_helix_buffer (buffer, buffer_len,
                                                       channel, load_package,
                                                       remote);
        break;

    case RC_CHANNEL_TYPE_DEBIAN:
        count = rc_extract_packages_from_debian_buffer (buffer, buffer_len,
                                                        channel, load_package,
                                                        remote);
        break;

    case RC_CHANNEL_TYPE_APTRPM:
        count = rc_extract_packages_from_aptrpm_buffer (buffer, buffer_len,
                                                        rc_packman_get_global (),
                                                        channel, load_package,
                                                        remote);
        break;

    default:
        rc_debug (RC_DEBUG_LEVEL_WARNING, "Unknown channel type for '%s'!",
                  rc_channel_get_id (channel));
        count = 0;
        break;
    }

    rc_debug (RC_DEBUG_LEVEL_DEBUG, "Loaded %d packages in '%s'",
              count, rc_channel_get_id (channel));

    if (decompressed_data)
        g_byte_array_free (decompressed_data, TRUE);
}

typedef struct {
    RCDWorldRemote *remote;
    RCChannel *channel;
} PerChannelData;

static void
channel_data_file_done_cb (RCDTransfer *t, gpointer user_data)
{
    PerChannelData *data = user_data;

    rcd_world_remote_parse_channel_data (data->remote,
                                         data->channel,
                                         t->data->data,
                                         t->data->len);

    g_object_unref (data->remote);
    rc_channel_unref (data->channel);
    g_free (data);
}

typedef struct {
    RCDWorldRemote *remote;
    gboolean local;
    RCDTransferPool *pool;
} ChannelData;

static gboolean
rcd_world_remote_per_channel_cb (RCChannel *channel,
                                 gpointer user_data)
{
    ChannelData *channel_data = user_data;
    char *url;
    RCDCacheEntry *entry;
    gboolean need_download;
    RCDTransfer *t;

    /*
     * First check to make sure this channel's distro targets match up
     * with ours.
     */
    if (!rc_channel_has_distro_target (channel, rc_distro_get_target (channel_data->remote->distro)))
        return TRUE;

    /* Stick the server's unique ID in front of the channel ID to amke it
       globally unique. */
    rc_channel_set_id_prefix (channel,
                              RC_WORLD_SERVICE (channel_data->remote)->unique_id);

    rc_world_store_add_channel (RC_WORLD_STORE (channel_data->remote),
                                channel);

    /* Channel data */
    entry = rcd_cache_lookup (rcd_cache_get_normal_cache (),
                              "channel_data", rc_channel_get_id (channel),
                              TRUE);

    need_download = TRUE;

    if (channel_data->local) {
        RCBuffer *buf;

        buf = rcd_cache_entry_map_file (entry);

        if (buf) {
            rcd_world_remote_parse_channel_data (channel_data->remote,
                                                 channel,
                                                 buf->data, buf->size);

            rc_buffer_unmap_file (buf);

            need_download = FALSE;
        }
    }

    if (need_download) {
        PerChannelData *per_channel_data;

        url = rcd_world_remote_get_channel_data_url (channel_data->remote,
                                                     channel);
        t = rcd_transfer_new (url, RCD_TRANSFER_FLAGS_BUFFER_DATA, entry);
        g_free (url);
    
        per_channel_data = g_new0 (PerChannelData, 1);
        per_channel_data->remote = g_object_ref (channel_data->remote);
        per_channel_data->channel = rc_channel_ref (channel);

        g_signal_connect (t, "file_done",
                          (GCallback) channel_data_file_done_cb,
                          per_channel_data);

        if (channel_data->pool == NULL) {
            channel_data->pool =
                rcd_transfer_pool_new (FALSE, "Package data download");
        }
    
        rcd_transfer_pool_add_transfer (channel_data->pool, t);
        g_object_unref (t);
    }
    
    /* Channel icon */
    entry = rcd_cache_lookup (rcd_cache_get_normal_cache (),
                              "icon", rc_channel_get_id (channel),
                              TRUE);

    need_download = TRUE;
    if (channel_data->local) {
        char *fn = rcd_cache_entry_get_local_filename (entry);

        if (g_file_test (fn, G_FILE_TEST_EXISTS))
            need_download = FALSE;

        g_free (fn);
    }

    if (need_download) {
        url = rcd_world_remote_get_channel_icon_url (channel_data->remote,
                                                     channel);
        t = rcd_transfer_new (url, RCD_TRANSFER_FLAGS_BUFFER_DATA, entry);
        g_free (url);

        if (channel_data->pool == NULL) {
            channel_data->pool =
                rcd_transfer_pool_new (FALSE, "Package data download");
        }

        rcd_transfer_pool_add_transfer (channel_data->pool, t);
        g_object_unref (t);
    }

    return TRUE;
}

static void
extract_service_info (RCDWorldRemote *remote,
                      const guint8   *buffer,
                      gint            buffer_len)
{
    RCWorldService *service = RC_WORLD_SERVICE (remote);
    xmlDoc *doc;
    xmlNode *root;
    char *tmp;

    doc = rc_parse_xml_from_buffer (buffer, buffer_len);
    if (!doc)
        return;

    root = xmlDocGetRootElement (doc);

    service->name = xml_get_prop (root, "name");

    if (!service->name)
        service->name = g_strdup (service->url);

    service->unique_id = xml_get_prop (root, "unique_id");

    if (!service->unique_id)
        service->unique_id = g_strdup (service->url);

    remote->contact_email = xml_get_prop (root, "contact_email");

    tmp = xml_get_prop (root, "premium_service");
    if (tmp && atoi (tmp) == 1)
        remote->premium_service = TRUE;
    g_free (tmp);

    remote->distributions_file = xml_get_prop (root, "distributions_file");
    remote->mirrors_file = xml_get_prop (root, "mirrors_file");
    remote->licenses_file = xml_get_prop (root, "licenses_file");
    remote->news_file = xml_get_prop (root, "news_file");

    xmlFreeDoc (doc);
}

static void
pending_complete_cb (RCPending *pending, gpointer user_data)
{
    RCWorld *world = RC_WORLD (user_data);

    rc_world_refresh_complete (world);

    g_object_unref (world);
}

static RCPending *
rcd_world_remote_parse_channels_xml (RCDWorldRemote *remote,
                                     gboolean        local,
                                     const guint8   *buffer,
                                     gint            buffer_len)
{
    ChannelData channel_data;
    int N;
    RCPending *pending = NULL;

    extract_service_info (remote, buffer, buffer_len);

    if (remote->distributions_file)
        rcd_world_remote_fetch_distributions (remote);
    else
        remote->distro = rc_distro_parse_xml (NULL, 0);

    /* FIXME: Handle unsupported distros */
    /*
     * We can't go on without distro info, so if it failed for some reason,
     * print and error and just ignore this service
     */
    if (!remote->distro) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Unknown distro info for '%s' [%s], not downloading "
                  "channel data", RC_WORLD_SERVICE (remote)->name,
                  RC_WORLD_SERVICE (remote)->unique_id);
        return NULL;
    }

    if (remote->mirrors_file)
        rcd_world_remote_fetch_mirrors (remote);

    if (remote->licenses_file)
        rcd_world_remote_fetch_licenses (remote);

    if (remote->news_file)
        rcd_world_remote_fetch_news (remote);

    channel_data.remote = remote;
    channel_data.local = local;
    channel_data.pool = NULL; /* May be set in _per_channel_cb() */

    N = rc_extract_channels_from_helix_buffer (buffer, buffer_len,
                                               rcd_world_remote_per_channel_cb,
                                               &channel_data);

    rc_debug (RC_DEBUG_LEVEL_DEBUG, "Got %d channels files", N);

    if (channel_data.pool != NULL) {
        rcd_transfer_pool_begin (channel_data.pool);
        pending = rcd_transfer_pool_get_pending (channel_data.pool);

        g_object_unref (channel_data.pool);
    }

    if (rc_world_is_refreshing (RC_WORLD (remote))) {
        if (pending) {
            g_signal_connect (pending, "complete",
                              (GCallback) pending_complete_cb,
                              g_object_ref (remote));
        } else
            rc_world_refresh_complete (RC_WORLD (remote));
    }

    return pending;
}

static RCPending *
rcd_world_remote_fetch (RCDWorldRemote *remote, gboolean local)
{
    char *url;
    RCDCacheEntry *entry;
    RCDTransfer *t;
    const GByteArray *data;

    url = g_strconcat (RC_WORLD_SERVICE (remote)->url,
                       "/channels.xml.gz", NULL);
    entry = rcd_cache_lookup_by_url (rcd_cache_get_normal_cache (),
                                     url, TRUE);

    if (local) {
        RCBuffer *buf;

        buf = rcd_cache_entry_map_file (entry);

        if (buf) {
            RCPending *pending;

            pending = rcd_world_remote_parse_channels_xml (remote, TRUE,
                                                           buf->data,
                                                           buf->size);

            rc_buffer_unmap_file (buf);
            g_free (url);

            return pending;
        }
    }

    t = rcd_transfer_new (url, RCD_TRANSFER_FLAGS_NONE, entry);
    g_free (url);

    data = rcd_transfer_begin_blocking (t);

    if (rcd_transfer_get_error (t)) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Attempt to download channel data failed: %s",
                  rcd_transfer_get_error_string (t));
        return RCD_WORLD_REMOTE_FETCH_FAILED;
    }

    return rcd_world_remote_parse_channels_xml (remote, FALSE,
                                                data->data, data->len);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

void
rcd_world_remote_add_license (RCDWorldRemote *remote,
                              const char     *name,
                              char           *license_text)
{
    g_return_if_fail (RCD_IS_WORLD_REMOTE (remote));
    g_return_if_fail (name != NULL);
    g_return_if_fail (license_text != NULL);

    if (!remote->licenses) {
        remote->licenses = g_hash_table_new_full (rc_str_case_hash,
                                                  rc_str_case_equal,
                                                  g_free, g_free);
    }

    g_hash_table_replace (remote->licenses, g_strdup (name), license_text);
}

void
rcd_world_remote_remove_license (RCDWorldRemote *remote,
                                 const char     *name)
{
    g_return_if_fail (RCD_IS_WORLD_REMOTE (remote));
    g_return_if_fail (name != NULL);

    if (remote->licenses)
        g_hash_table_remove (remote->licenses, name);
}

void
rcd_world_remote_clear_licenses (RCDWorldRemote *remote)
{
    g_return_if_fail (RCD_IS_WORLD_REMOTE (remote));

    if (remote->licenses) {
        g_hash_table_destroy (remote->licenses);
        remote->licenses = NULL;
    }
}

const char *
rcd_world_remote_lookup_license (RCDWorldRemote *remote,
                                 const char     *name)
{
    g_return_val_if_fail (RCD_IS_WORLD_REMOTE (remote), NULL);

    if (!remote->licenses)
        return NULL;

    return g_hash_table_lookup (remote->licenses, name);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

void
rcd_world_remote_add_mirror (RCDWorldRemote *remote,
                             RCDMirror      *mirror)
{
    g_return_if_fail (RCD_IS_WORLD_REMOTE (remote));
    g_return_if_fail (mirror != NULL);

    remote->mirrors = g_slist_prepend (remote->mirrors, mirror);
}

void
rcd_world_remote_clear_mirrors (RCDWorldRemote *remote)
{
    GSList *iter;

    g_return_if_fail (RCD_IS_WORLD_REMOTE (remote));

    for (iter = remote->mirrors; iter != NULL; iter = iter->next) {
        RCDMirror *mirror = iter->data;
        rcd_mirror_free (mirror);
    }

    g_slist_free (remote->mirrors);
    remote->mirrors = NULL;
}

void
rcd_world_remote_foreach_mirror (RCDWorldRemote                *remote,
                                 RCDWorldRemoteForeachMirrorFn  fn,
                                 gpointer                       user_data)
{
    GSList *iter;

    g_return_if_fail (RCD_IS_WORLD_REMOTE (remote));
    g_return_if_fail (fn != NULL);

    for (iter = remote->mirrors; iter != NULL; iter = iter->next) {
        fn ((RCDMirror *) iter->data, user_data);
    }
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

void
rcd_world_remote_add_news (RCDWorldRemote *remote, RCDNews *news)
{
    g_return_if_fail (RCD_IS_WORLD_REMOTE (remote));
    g_return_if_fail (news != NULL);

    remote->news_items = g_slist_append (remote->news_items, news);
}

void
rcd_world_remote_clear_news (RCDWorldRemote *remote)
{
    GSList *iter;

    g_return_if_fail (RCD_IS_WORLD_REMOTE (remote));

    for (iter = remote->news_items; iter != NULL; iter = iter->next) {
        RCDNews *news = iter->data;

        rcd_news_free (news);
    }

    g_slist_free (remote->news_items);
    remote->news_items = NULL;
}

void
rcd_world_remote_foreach_news (RCDWorldRemote              *remote,
                               RCDWorldRemoteForeachNewsFn  fn,
                               gpointer                     user_data)
{
    GSList *iter;

    g_return_if_fail (RCD_IS_WORLD_REMOTE (remote));
    g_return_if_fail (fn != NULL);

    for (iter = remote->news_items; iter != NULL; iter = iter->next) {
        fn ((RCDNews *) iter->data, user_data);
    }
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

RCWorld *
rcd_world_remote_new (const char *url)
{
    RCDWorldRemote *remote;

    g_return_val_if_fail (url && *url, NULL);

    remote = g_object_new (RCD_TYPE_WORLD_REMOTE, NULL);

    RC_WORLD_SERVICE (remote)->url = g_strdup (url);

    return (RCWorld *) remote;
}

void
rcd_world_remote_register_service (void)
{
    rc_world_service_register ("http", RCD_TYPE_WORLD_REMOTE);
    rc_world_service_register ("https", RCD_TYPE_WORLD_REMOTE);
}
