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
#include <sys/utsname.h>
#include <unistd.h>

#include <libredcarpet.h>

#include "rcd-license.h"
#include "rcd-news.h"
#include "rcd-prefs.h"
#include "rcd-transfer-pool.h"
#include "rcd-rpc-util.h"
#include "rcd-xmlrpc.h"

static RCWorldServiceClass *parent_class;

static RCPending *rcd_world_remote_fetch (RCDWorldRemote  *remote,
                                          gboolean         local,
                                          GError         **error);

static void
rcd_world_remote_finalize (GObject *obj)
{
    RCDWorldRemote *remote = RCD_WORLD_REMOTE (obj);

    g_free (remote->contact_email);
    g_free (remote->activation_root_url);
    g_free (remote->distributions_url);
    g_free (remote->mirrors_url);
    g_free (remote->licenses_url);
    g_free (remote->news_url);
    g_free (remote->channels_url);

    if (remote->distro)
        rc_distro_free (remote->distro);

    rcd_world_remote_clear_mirrors (remote);
    rcd_world_remote_clear_licenses (remote);
    rcd_world_remote_clear_news (remote);

    rcd_identity_remove_backend (remote->identity_backend);
    g_free (remote->identity_backend);

    g_slist_foreach (remote->identities, (GFunc) rcd_identity_free, NULL);
    g_slist_free (remote->identities);

    if (G_OBJECT_CLASS (parent_class)->finalize)
        G_OBJECT_CLASS (parent_class)->finalize (obj);
}

static RCPending *
rcd_world_remote_refresh (RCWorld *world)
{
    rc_world_refresh_begin (world);

    return rcd_world_remote_fetch (RCD_WORLD_REMOTE (world), FALSE, NULL);
}

static gboolean
rcd_world_remote_assemble (RCWorldService *service, GError **error)
{
    char *query_part;
    gboolean local = TRUE;
    RCPending *pending;
    GError *tmp_error = NULL;

    /* Find the query part. */
    query_part = strchr (service->url, '?');

    if (query_part) {
        char *url;

        url = g_strndup (service->url, query_part - service->url);

        /* Move past the '?' */
        query_part++;

        if (g_strncasecmp (query_part, "remote_only=1", 13) == 0)
            local = FALSE;

        g_free (service->url); 
        service->url = url;
   }

    pending = rcd_world_remote_fetch (RCD_WORLD_REMOTE (service),
                                      local, &tmp_error);

    if (tmp_error != NULL) {
        g_propagate_error (error, tmp_error);
        return FALSE;
    }

    return TRUE;
}

static RCDIdentity *
lookup_identity (RCDIdentityBackend *backend, const char *username)
{
    RCDWorldRemote *remote = RCD_WORLD_REMOTE (backend->user_data);
    GSList *iter;

    for (iter = remote->identities; iter; iter = iter->next) {
        RCDIdentity *identity = iter->data;

        if (!strcmp (identity->username, username))
            return rcd_identity_copy (identity);
    }

    return NULL;
}

static void
foreach_identity (RCDIdentityBackend *backend, RCDIdentityFn fn,
                  gpointer user_data)
{
    RCDWorldRemote *remote = RCD_WORLD_REMOTE (backend->user_data);
    GSList *iter;

    for (iter = remote->identities; iter; iter = iter->next) {
        RCDIdentity *identity = iter->data;

        fn (identity, user_data);
    }
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
    remote->identity_backend = rcd_identity_backend_new (FALSE);
    remote->identity_backend->is_editable = FALSE;
    remote->identity_backend->user_data = remote;
    remote->identity_backend->lookup_fn = lookup_identity;
    remote->identity_backend->foreach_fn = foreach_identity;

    rcd_identity_add_backend (remote->identity_backend);
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
rcd_world_remote_fetch_distributions (RCDWorldRemote *remote, gboolean local)
{
    RCDCacheEntry *entry;
    RCDTransfer *t = NULL;
    RCBuffer *buf = NULL;
    const guint8 *buffer;
    gsize buffer_len;

    entry = rcd_cache_lookup (rcd_cache_get_normal_cache (),
                              "distro_info",
                              RC_WORLD_SERVICE (remote)->unique_id,
                              TRUE);
    
    if (local) {
        buf = rcd_cache_entry_map_file (entry);

        if (buf) {
            buffer = buf->data;
            buffer_len = buf->size;
        }
    }

    if (!buf) {
        RCDTransfer *t;
        const GByteArray *data;

        t = rcd_transfer_new (remote->distributions_url,
                              RCD_TRANSFER_FLAGS_NONE, entry);

        data = rcd_transfer_begin_blocking (t);

        if (rcd_transfer_get_error (t)) {
            rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                      "Unable to downloaded distribution info: %s",
                      rcd_transfer_get_error_string (t));
            goto cleanup;
        }

        buffer = data->data;
        buffer_len = data->len;
    }

    remote->distro = rc_distro_parse_xml (buffer, buffer_len);

    if (!remote->distro) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Unable to parse distribution info");
        rcd_cache_entry_invalidate (entry);
    }

cleanup:
    if (buf)
        rc_buffer_unmap_file (buf);

    if (t)
        g_object_unref (t);
}

static void
rcd_world_remote_fetch_licenses (RCDWorldRemote *remote, gboolean local)
{
    RCDCacheEntry *entry;
    RCDTransfer *t = NULL;
    RCBuffer *buf = NULL;
    const guint8 *buffer;
    gsize buffer_len;

    entry = rcd_cache_lookup (rcd_cache_get_normal_cache (),
                              "licenses", RC_WORLD_SERVICE (remote)->unique_id,
                              TRUE);

    if (local) {
        buf = rcd_cache_entry_map_file (entry);

        if (buf) {
            buffer = buf->data;
            buffer_len = buf->size;
        }
    }

    if (!buf) {
        const GByteArray *data;

        t = rcd_transfer_new (remote->licenses_url,
                              RCD_TRANSFER_FLAGS_NONE, entry);

        data = rcd_transfer_begin_blocking (t);

        if (rcd_transfer_get_error (t)) {
            rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                      "Unable to downloaded licenses info: %s",
                      rcd_transfer_get_error_string (t));
            goto cleanup;
        }

        buffer = data->data;
        buffer_len = data->len;
    }

    if (!rcd_license_parse (remote, buffer, buffer_len)) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL, "Unable to parse licenses info");
        rcd_cache_entry_invalidate (entry);
    }        

cleanup:
    if (buf)
        rc_buffer_unmap_file (buf);
    
    if (t)
        g_object_unref (t);
}

static void
rcd_world_remote_fetch_news (RCDWorldRemote *remote, gboolean local)
{
    RCDCacheEntry *entry;
    RCDTransfer *t = NULL;
    RCBuffer *buf = NULL;
    const guint8 *buffer;
    gsize buffer_len;
    xmlDoc *doc;
    xmlNode *node;

    entry = rcd_cache_lookup (rcd_cache_get_normal_cache (),
                              "news", RC_WORLD_SERVICE (remote)->unique_id,
                              TRUE);

    if (local) {
        buf = rcd_cache_entry_map_file (entry);

        if (buf) {
            buffer = buf->data;
            buffer_len = buf->size;
        }
    }

    if (!buf) {
        const GByteArray *data;

        t = rcd_transfer_new (remote->news_url,
                              RCD_TRANSFER_FLAGS_NONE, entry);

        data = rcd_transfer_begin_blocking (t);

        if (rcd_transfer_get_error (t)) {
            rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                      "Unable to downloaded licenses info: %s",
                      rcd_transfer_get_error_string (t));
            goto cleanup;
        }

        buffer = data->data;
        buffer_len = data->len;
    }

    doc = rc_parse_xml_from_buffer (buffer, buffer_len);
    if (doc == NULL) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL, "Couldn't parse news XML file");
        rcd_cache_entry_invalidate (entry);
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
    if (buf)
        rc_buffer_unmap_file (buf);

    if (t)
        g_object_unref (t);
}

static void
rcd_world_remote_fetch_mirrors (RCDWorldRemote *remote, gboolean local)
{
    RCDCacheEntry *entry;
    RCDTransfer *t = NULL;
    RCBuffer *buf = NULL;
    const guint8 *buffer;
    gsize buffer_len;
    xmlDoc *doc = NULL;
    xmlNode *node;

    entry = rcd_cache_lookup (rcd_cache_get_normal_cache (),
                              "mirrors", RC_WORLD_SERVICE (remote)->unique_id,
                              TRUE);

    if (local) {
        buf = rcd_cache_entry_map_file (entry);

        if (buf) {
            buffer = buf->data;
            buffer_len = buf->size;
        }
    }

    if (!buf) {
        const GByteArray *data;

        t = rcd_transfer_new (remote->mirrors_url,
                              RCD_TRANSFER_FLAGS_NONE, entry);

        data = rcd_transfer_begin_blocking (t);

        if (rcd_transfer_get_error (t)) {
            rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                      "Attempt to download mirror list failed: %s",
                      rcd_transfer_get_error_string (t));
            goto cleanup;
        }

        buffer = data->data;
        buffer_len = data->len;
    }

    doc = rc_parse_xml_from_buffer (buffer, buffer_len);
    if (doc == NULL) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL, "Couldn't parse mirrors XML file.");
        rcd_cache_entry_invalidate (entry);
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
    if (buf)
        rc_buffer_unmap_file (buf);

    if (t)
        g_object_unref (t);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */


static xmlrpc_value *
build_register_params (xmlrpc_env *env,
                       const char *activation_code,
                       const char *email,
                       const char *alias)
{
    struct utsname uname_buf;
    const char *hostname;
    xmlrpc_value *value;

    if (uname (&uname_buf) < 0) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Couldn't get hostname from uname()");
        hostname = "(unknown)";
    }
    else
        hostname = uname_buf.nodename;

    value = xmlrpc_struct_new (env);
    XMLRPC_FAIL_IF_FAULT (env);

    if (!activation_code) {
        /*
          g_assert (rcd_prefs_get_org_id ());
          RCD_XMLRPC_STRUCT_SET_STRING (env, value,
          "orgtoken",
          rcd_prefs_get_org_id ());
          XMLRPC_FAIL_IF_FAULT (env);
        */
    } else {
        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "key", activation_code);
        XMLRPC_FAIL_IF_FAULT (env);
    }
 
    if (email) {
        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "email", email);
        XMLRPC_FAIL_IF_FAULT (env);
    }

    if (alias) {
        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "alias", alias);
        XMLRPC_FAIL_IF_FAULT (env);
    }

    RCD_XMLRPC_STRUCT_SET_STRING (env, value, "hostname", hostname);
    XMLRPC_FAIL_IF_FAULT (env);

cleanup:
    if (env->fault_occurred) {
        xmlrpc_DECREF (value);
        value = NULL;
    }
 
    return value;
}

gboolean
rcd_world_remote_activate (RCDWorldRemote  *remote,
                           const char      *activation_code,
                           const char      *email,
                           const char      *alias,
                           char           **err_msg)
{
    xmlrpc_env env;
    xmlrpc_server_info *server;
    xmlrpc_value *params, *value;
    gboolean success = TRUE;

    if (err_msg)
        *err_msg = NULL;

    g_return_val_if_fail (RCD_IS_WORLD_REMOTE (remote), FALSE);

    xmlrpc_env_init (&env);

    server = rcd_xmlrpc_get_server (&env, remote->activation_root_url);
    XMLRPC_FAIL_IF_FAULT (&env);

    params = build_register_params (&env, activation_code, email, alias);
    XMLRPC_FAIL_IF_FAULT (&env);

    value = xmlrpc_client_call_server (&env, server,
                                       "rcserver.activate",
                                       "(V)", params);

cleanup:
    if (env.fault_occurred) {
        rc_debug (RC_DEBUG_LEVEL_WARNING, "Unable to activate with '%s': %s",
                  remote->activation_root_url, env.fault_string);

        if (err_msg)
            *err_msg = g_strdup (env.fault_string);

        success = FALSE;
    } else
        xmlrpc_DECREF (value);

    xmlrpc_server_info_free (server);
    xmlrpc_env_clean (&env);

    return success;
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

    if (!rcd_transfer_get_error (t)) {
        rcd_world_remote_parse_channel_data (data->remote,
                                             data->channel,
                                             t->data->data,
                                             t->data->len);
    }

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
pending_complete_cb (RCPending *pending, gpointer user_data)
{
    RCWorld *world = RC_WORLD (user_data);

    rc_world_refresh_complete (world);

    g_object_unref (world);
}

static gboolean
remove_channel_cb (RCChannel *channel, gpointer user_data)
{
    RCWorldStore *store = RC_WORLD_STORE (user_data);

    rc_world_store_remove_channel (store, channel);

    return TRUE;
}

static RCPending *
rcd_world_remote_fetch_channels (RCDWorldRemote *remote, gboolean local,
                                 GError **error)
{
    RCDCacheEntry *entry;
    RCDTransfer *t = NULL;
    RCPending *pending = NULL;
    ChannelData channel_data;
    int N;
    RCBuffer *buf = NULL;
    const guint8 *buffer;
    gsize buffer_len;

    entry = rcd_cache_lookup (rcd_cache_get_normal_cache (),
                              "channel_list",
                              RC_WORLD_SERVICE (remote)->unique_id,
                              TRUE);

    if (local) {
        buf = rcd_cache_entry_map_file (entry);

        if (buf) {
            buffer = buf->data;
            buffer_len = buf->size;
        }
    }

    if (!buf) {
        const GByteArray *data;

        t = rcd_transfer_new (remote->channels_url,
                              RCD_TRANSFER_FLAGS_NONE, entry);

        data = rcd_transfer_begin_blocking (t);

        if (rcd_transfer_get_error (t)) {
            g_set_error (error, RC_ERROR, RC_ERROR,
                         "Unable to download channel list: %s",
                         rcd_transfer_get_error_string (t));
            rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                      "Unable to downloaded channel list: %s",
                      rcd_transfer_get_error_string (t));
            goto cleanup;
        }

        buffer = data->data;
        buffer_len = data->len;
    }

    /* Clear out the old channel and package data */
    rc_world_foreach_channel (RC_WORLD (remote), remove_channel_cb, remote);

    channel_data.remote = remote;
    channel_data.local = local;
    channel_data.pool = NULL; /* May be set in _per_channel_cb() */

    N = rc_extract_channels_from_helix_buffer (buffer, buffer_len,
                                               rcd_world_remote_per_channel_cb,
                                               &channel_data);

    rc_debug (RC_DEBUG_LEVEL_DEBUG, "Got %d channels files", N);

    if (N < 0) {
        /* Don't cache invalid data */
        rcd_cache_entry_invalidate (entry);

        g_set_error (error, RC_ERROR, RC_ERROR,
                     "Invalid channel data");
        goto cleanup;
    }

    if (channel_data.pool != NULL) {
        rcd_transfer_pool_begin (channel_data.pool);
        pending = rcd_transfer_pool_get_pending (channel_data.pool);

        g_object_unref (channel_data.pool);
    }

    if (rc_world_is_refreshing (RC_WORLD (remote))) {
        if (pending != NULL) {
            g_signal_connect (pending, "complete",
                              (GCallback) pending_complete_cb,
                              g_object_ref (remote));
        } else
            rc_world_refresh_complete (RC_WORLD (remote));
    }

cleanup:
    if (buf)
        rc_buffer_unmap_file (buf);

    if (t)
        g_object_unref (t);

    return pending;
}

static void
got_privs_cb (char *server_url, char *method_name, xmlrpc_value *param_array,
              void *user_data, xmlrpc_env *fault, xmlrpc_value *result)
{
    RCDWorldRemote *remote = RCD_WORLD_REMOTE (user_data);
    GSList *prev_identities;
    xmlrpc_env env;
    int size = 0, i;

    if (fault->fault_occurred) {
        rc_debug (RC_DEBUG_LEVEL_ERROR,
                  "Unable to download privileges from %s: %s",
                  RC_WORLD_SERVICE (remote)->url, fault->fault_string);
        return;
    }

    prev_identities = remote->identities;
    remote->identities = NULL;

    xmlrpc_env_init (&env);

    size = xmlrpc_array_size (&env, result);
    XMLRPC_FAIL_IF_FAULT (&env);

    for (i = 0; i < size; i++) {
        xmlrpc_value *v;
        char *username, *password, *privs;
        RCDIdentity *identity;

        v = xmlrpc_array_get_item (&env, result, i);
        XMLRPC_FAIL_IF_FAULT (&env);

        RCD_XMLRPC_STRUCT_GET_STRING (&env, v, "username", username);

        identity = rcd_identity_lookup (username);

        /* Check to see if this username already has an identity */
        if (identity) {
            rc_debug (RC_DEBUG_LEVEL_WARNING,
                      "Not replacing existing identity for '%s'",
                      username);

            rcd_identity_free (identity);
            g_free (username);
        } else {
            RCD_XMLRPC_STRUCT_GET_STRING (&env, v, "password", password);

            RCD_XMLRPC_STRUCT_GET_STRING (&env, v, "privs", privs);

            identity = rcd_identity_new ();
            identity->username = username;
            identity->password = password;
            identity->privileges = rcd_privileges_from_string (privs);
            g_free (privs);

            remote->identities = g_slist_prepend (remote->identities,
                                                  identity);
        }
    }

cleanup:
    if (env.fault_occurred) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Privilege information from the server is malformed: %s",
                  env.fault_string);
        g_slist_foreach (remote->identities, (GFunc) rcd_identity_free, NULL);
        g_slist_free (remote->identities);
        remote->identities = prev_identities;
    } else {
        g_slist_foreach (prev_identities, (GFunc) rcd_identity_free, NULL);
        g_slist_free (prev_identities);
    }
}

static void
rcd_world_remote_fetch_privileges (RCDWorldRemote *remote)
{
    xmlrpc_env env;
    xmlrpc_server_info *server_info;

    xmlrpc_env_init (&env);

    server_info = rcd_xmlrpc_get_server (&env, RC_WORLD_SERVICE (remote)->url);
    XMLRPC_FAIL_IF_FAULT (&env);

    xmlrpc_client_call_server_asynch (server_info, "rcserver.machine.getPrivs",
                                      got_privs_cb, remote, "()");

    xmlrpc_server_info_free (server_info);

cleanup:
    if (env.fault_occurred) {
        rc_debug (RC_DEBUG_LEVEL_ERROR,
                  "Unable to download privileges from %s",
                  RC_WORLD_SERVICE (remote)->url);
    }

    xmlrpc_env_clean (&env);
}

static gboolean
is_supported_distro (RCDistro *distro)
{
    RCDistroStatus status = rc_distro_get_status (distro);
    const char *distro_name;
    time_t death_date = rc_distro_get_death_date (distro);
    char *death_str = NULL;
    gboolean download_data = FALSE;

    {
        char *ctime_sucks;
        int len;

        ctime_sucks = ctime (&death_date);
        len = strlen (ctime_sucks);
        death_str = g_strndup (ctime_sucks, len - 1);
    }

    if (status != RC_DISTRO_STATUS_SUPPORTED) {
        rc_debug (RC_DEBUG_LEVEL_ALWAYS, "*** NOTICE ***");
        rc_debug (RC_DEBUG_LEVEL_ALWAYS, "");
    }

    distro_name = rc_distro_get_target (distro);
    if (!distro_name)
        distro_name = "unknown";

    switch (status) {
    case RC_DISTRO_STATUS_UNSUPPORTED:
        rc_debug (RC_DEBUG_LEVEL_ALWAYS,
                  "The distribution you are running (%s) is not",
                  distro_name);
        rc_debug (RC_DEBUG_LEVEL_ALWAYS,
                  "supported by this server.  Channel data will not be "
                  "downloaded.");
        break;

    case RC_DISTRO_STATUS_PRESUPPORTED:
        rc_debug (RC_DEBUG_LEVEL_ALWAYS,
                  "The distribution you are running (%s) is not",
                  distro_name);
        rc_debug (RC_DEBUG_LEVEL_ALWAYS,
                  "yet supported by this server.  Channel data will not be "
                  "downloaded.");
        break;

    case RC_DISTRO_STATUS_SUPPORTED:
        download_data = TRUE;
        break;

    case RC_DISTRO_STATUS_DEPRECATED:
        rc_debug (RC_DEBUG_LEVEL_ALWAYS,
                  "Support for the distribution you are running (%s) has ",
                  distro_name);
        rc_debug (RC_DEBUG_LEVEL_ALWAYS,
                  "been deprecated on this server and will be discontinued "
                  "on %s.",
                  death_str);
        rc_debug (RC_DEBUG_LEVEL_ALWAYS,
                  "After that date you will need to upgrade your "
                  "distribution to continue");
        rc_debug (RC_DEBUG_LEVEL_ALWAYS,
                  "using this server for package installations and upgrades.");
        download_data = TRUE;
        break;

    case RC_DISTRO_STATUS_RETIRED:
        rc_debug (RC_DEBUG_LEVEL_ALWAYS,
                  "As of %s, support for the distribution you are",
                  death_str);
        rc_debug (RC_DEBUG_LEVEL_ALWAYS,
                  "running (%s) has been discontinued on this server.  You ",
                  distro_name);
        rc_debug (RC_DEBUG_LEVEL_ALWAYS,
                  "must upgrade your distribution to use channels for package "
                  "installations");
        rc_debug (RC_DEBUG_LEVEL_ALWAYS,
                  "and upgrades.  Channel data will not be downloaded.");
        break;
    }

    if (status != RC_DISTRO_STATUS_SUPPORTED) {
        rc_debug (RC_DEBUG_LEVEL_ALWAYS, "");
    }

    g_free (death_str);

    return download_data;
}

static gboolean
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
        return FALSE;

    root = xmlDocGetRootElement (doc);

    if (g_strcasecmp (root->name, "service") != 0)
        return FALSE;

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

    remote->activation_root_url = xml_get_prop (root, "activation_root_url");

    if (!remote->activation_root_url)
        remote->activation_root_url = g_strdup (service->url);

    tmp = xml_get_prop (root, "distributions_file");
    if (tmp) {
        remote->distributions_url = rc_maybe_merge_paths (service->url, tmp);
        g_free (tmp);
    }

    tmp = xml_get_prop (root, "mirrors_file");
    if (tmp) {
        remote->mirrors_url = rc_maybe_merge_paths (service->url, tmp);
        g_free (tmp);
    }

    tmp = xml_get_prop (root, "licenses_file");
    if (tmp) {
        remote->licenses_url = rc_maybe_merge_paths (service->url, tmp);
        g_free (tmp);
    }

    tmp = xml_get_prop (root, "news_file");
    if (tmp) {
        remote->news_url = rc_maybe_merge_paths (service->url, tmp);
        g_free (tmp);
    }

    tmp = xml_get_prop (root, "channels_file");
    if (tmp) {
        remote->channels_url = rc_maybe_merge_paths (service->url, tmp);
        g_free (tmp);
    }

    xmlFreeDoc (doc);
    
    return TRUE;
}

static RCPending *
rcd_world_remote_parse_serviceinfo (RCDWorldRemote  *remote,
                                    gboolean         local,
                                    const guint8    *buffer,
                                    gint             buffer_len,
                                    GError         **error)
{
    RCPending *pending = NULL;
    GError *tmp_error = NULL;

    if (!extract_service_info (remote, buffer, buffer_len)) {
        g_set_error (error, RC_ERROR, RC_ERROR,
                     "Unable to parse service info");
        rc_debug (RC_DEBUG_LEVEL_CRITICAL, "Unable to parse service info");
        return NULL;
    }

    if (remote->premium_service && rcd_prefs_get_org_id ()) {
        rcd_world_remote_activate (remote, NULL, NULL, NULL, NULL);
    }

    if (remote->distributions_url)
        rcd_world_remote_fetch_distributions (remote, local);
    else
        remote->distro = rc_distro_parse_xml (NULL, 0);

    /*
     * We can't go on without distro info, so if it failed for some reason,
     * print and error and just ignore this service
     */
    if (!remote->distro) {
        rc_debug (RC_DEBUG_LEVEL_INFO,
                  "Unknown distro info for '%s' [%s], not downloading "
                  "channel data", RC_WORLD_SERVICE (remote)->name,
                  RC_WORLD_SERVICE (remote)->unique_id);
        g_set_error (error, RC_ERROR, RC_ERROR,
                     "Unable to determine distribution type");
        return NULL;
    } else {
        if (!is_supported_distro (remote->distro)) {
            g_set_error (error, RC_ERROR, RC_ERROR,
                         "%s %s (%s) is not a supported distribution",
                         rc_distro_get_name (remote->distro),
                         rc_distro_get_version (remote->distro),
                         rc_distro_get_target (remote->distro));
            rc_debug (RC_DEBUG_LEVEL_INFO,
                      "%s %s (%s) is not a supported distro for '%s' [%s]",
                      rc_distro_get_name (remote->distro),
                      rc_distro_get_version (remote->distro),
                      rc_distro_get_target (remote->distro),
                      RC_WORLD_SERVICE (remote)->name,
                      RC_WORLD_SERVICE (remote)->unique_id);
            return NULL;
        }
    }

    if (remote->channels_url)
        pending = rcd_world_remote_fetch_channels (remote, local, &tmp_error);

    if (tmp_error) {
        g_propagate_error (error, tmp_error);
        return NULL;
    }

    if (remote->mirrors_url)
        rcd_world_remote_fetch_mirrors (remote, local);

    if (remote->licenses_url)
        rcd_world_remote_fetch_licenses (remote, local);

    if (remote->news_url)
        rcd_world_remote_fetch_news (remote, local);

    if (remote->premium_service)
        rcd_world_remote_fetch_privileges (remote);

    return pending;
}

static RCPending *
rcd_world_remote_fetch (RCDWorldRemote *remote, gboolean local, GError **error)
{
    char *url;
    char *cache_entry_str;
    RCDCacheEntry *entry;
    RCDTransfer *t;
    const GByteArray *data;
    RCPending *pending;
    GError *tmp_error = NULL;

    if (!strncmp (RC_WORLD_SERVICE (remote)->url, "http://", 7))
        cache_entry_str = g_strdup (RC_WORLD_SERVICE (remote)->url + 7);
    else if (!strncmp (RC_WORLD_SERVICE (remote)->url, "https://", 8)) {
        cache_entry_str = g_strconcat ("s:",
                                       RC_WORLD_SERVICE (remote)->url + 8,
                                       NULL);
    } else
        g_assert_not_reached ();
                       
    entry = rcd_cache_lookup (rcd_cache_get_normal_cache (),
                              "service_info", cache_entry_str, TRUE);
    g_free (cache_entry_str);

    if (local) {
        RCBuffer *buf;

        buf = rcd_cache_entry_map_file (entry);

        if (buf) {
            RCPending *pending;

            pending = rcd_world_remote_parse_serviceinfo (remote, TRUE,
                                                          buf->data,
                                                          buf->size,
                                                          &tmp_error);

            rc_buffer_unmap_file (buf);

            if (tmp_error == NULL)
                return pending;
            else {
                g_error_free (tmp_error);
                /* 
                 * The data is bad on disk, so let's invalidate the
                 * cache entry so we download it again
                 */
                rcd_cache_entry_invalidate (entry);
            }
        }
    }

    url = g_strconcat (RC_WORLD_SERVICE (remote)->url,
                       "/serviceinfo.xml", NULL);
    t = rcd_transfer_new (url, RCD_TRANSFER_FLAGS_NONE, entry);
    g_free (url);

    data = rcd_transfer_begin_blocking (t);

    if (rcd_transfer_get_error (t)) {
        g_set_error (error, RC_ERROR, RC_ERROR,
                     "Unable to download service info: %s",
                     rcd_transfer_get_error_string (t));
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Unable to download service info: %s",
                  rcd_transfer_get_error_string (t));
        return NULL;
    }

    pending = rcd_world_remote_parse_serviceinfo (remote, FALSE,
                                                  data->data, data->len,
                                                  &tmp_error);
        
    if (tmp_error != NULL) {
        /* We don't want to cache bad data */
        rcd_cache_entry_invalidate (entry);

        /*
         * If an error has occurred, we'll need to say that the refresh
         * is finished.
         */
        if (rc_world_is_refreshing (RC_WORLD (remote)))
            rc_world_refresh_complete (RC_WORLD (remote));

        g_propagate_error (error, tmp_error);
    }

    return pending;
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
