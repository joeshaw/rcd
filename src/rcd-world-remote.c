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
#include "rcd-marshal.h"
#include "rcd-news.h"
#include "rcd-prefs.h"
#include "rcd-transfer-pool.h"
#include "rcd-rpc-util.h"
#include "rcd-xmlrpc.h"

static RCWorldServiceClass *parent_class;

enum {
    ACTIVATED,
    LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

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

    if (G_OBJECT_CLASS (parent_class)->finalize)
        G_OBJECT_CLASS (parent_class)->finalize (obj);
}

static RCPending *
rcd_world_remote_refresh (RCWorld *world)
{
    RCPending *pending;

    rc_world_refresh_begin (world);

    pending = rcd_world_remote_fetch (RCD_WORLD_REMOTE (world), FALSE, NULL);

    if (pending == NULL)
        rc_world_refresh_complete (world);

    return pending;
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

    /* Validate the URL */
    if (strncmp (service->url, "http://", 7)
        && strncmp (service->url, "https://", 8)) {
        g_set_error (error, RC_ERROR, RC_ERROR,
                     "Malformed URL: %s", service->url);
        return FALSE;
    }

    pending = rcd_world_remote_fetch (RCD_WORLD_REMOTE (service),
                                      local, &tmp_error);

    if (tmp_error != NULL) {
        g_propagate_error (error, tmp_error);
        return FALSE;
    }

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

    world_class->refresh_fn = rcd_world_remote_refresh;

    service_class->assemble_fn = rcd_world_remote_assemble;

    signals[ACTIVATED] =
        g_signal_new ("activated",
                      G_TYPE_FROM_CLASS (klass),
                      G_SIGNAL_RUN_LAST,
                      G_STRUCT_OFFSET (RCDWorldRemoteClass, activated),
                      NULL, NULL,
                      rcd_marshal_VOID__VOID,
                      G_TYPE_NONE, 0);
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
rcd_world_remote_fetch_distributions (RCDWorldRemote *remote, gboolean local)
{
    RCDCacheEntry *entry;
    RCDTransfer *t = NULL;
    RCBuffer *buf = NULL;
    const guint8 *buffer = NULL;
    gsize buffer_len = 0;

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

    if (!buffer) {
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

    g_assert (buffer != NULL);

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
    const guint8 *buffer = NULL;
    gsize buffer_len = 0;

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

    if (!buffer) {
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

    g_assert (buffer != NULL);

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
    const guint8 *buffer = NULL;
    gsize buffer_len = 0;
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

    if (!buffer) {
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

    g_assert (buffer != NULL);

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
    const guint8 *buffer = NULL;
    gsize buffer_len = 0;
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

    if (!buffer) {
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

    g_assert (buffer != NULL);

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

    RCD_XMLRPC_STRUCT_SET_INT (env, value, "port",
                               rcd_prefs_get_remote_server_port ());

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
    char *new_url;

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
    XMLRPC_FAIL_IF_FAULT (&env);

    xmlrpc_parse_value (&env, value, "s", &new_url);

cleanup:
    if (env.fault_occurred) {
        rc_debug (RC_DEBUG_LEVEL_WARNING, "Unable to activate with '%s': %s",
                  remote->activation_root_url, env.fault_string);

        if (err_msg)
            *err_msg = g_strdup (env.fault_string);

        success = FALSE;
    } else {
        if (XMLRPC_STRING_TO_RC (new_url) != NULL) {
            RCWorldService *service = RC_WORLD_SERVICE (remote);

            g_free (service->url);
            service->url = g_strdup (new_url);

            rc_world_refresh (RC_WORLD (remote));
        }

        g_signal_emit (remote, signals[ACTIVATED], 0);

        xmlrpc_DECREF (value);
    }

    xmlrpc_server_info_free (server);
    xmlrpc_env_clean (&env);

    return success;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static gboolean
prepend_package (RCPackage *package, gpointer user_data)
{
    GSList **slist = (GSList **) user_data;
    *slist = g_slist_prepend (*slist, rc_package_ref (package));

    return TRUE;
}

static gint
compare_package_for_store (gconstpointer a, gconstpointer b,
                           gpointer user_data)
{
    RCPackage *pa = (RCPackage *) a;
    RCPackage *pb = (RCPackage *) b;
    GSList *compat_arch_list = (GSList *) user_data;
    int a_arch_score;
    int b_arch_score;
    int result;

    /* Basic sort by name */
    result = rc_package_spec_compare_name (RC_PACKAGE_SPEC (pa),
                                           RC_PACKAGE_SPEC (pb));
    if (result != 0)
        return result;

    /* Get higher-versioned packages first in the list */
    result = rc_packman_version_compare (rc_packman_get_global (),
                                         RC_PACKAGE_SPEC (pa),
                                         RC_PACKAGE_SPEC (pb));
    if (result != 0)
        return result;

    /* Same name, same version.  Get the best arch score first. */
    a_arch_score = rc_arch_get_compat_score (compat_arch_list,
                                             pa->arch);
    b_arch_score = rc_arch_get_compat_score (compat_arch_list,
                                             pb->arch);

    if (a_arch_score > b_arch_score)
        return -1;
    else if (a_arch_score < b_arch_score)
        return 1;
    else
        return 0;
}

static gboolean
parse_nevra (const char *orig_input,
             char **name_out, guint32 *epoch_out,
             char **version_out, char **release_out,
             char **arch_out)
{
    char *arch_sep;
    char *release_sep;
    char *ver_sep;
    char *epoch_sep;
    char *epoch_str;
    char *input;
    gboolean ret = TRUE;

    input = g_strdup (orig_input);
    
    arch_sep = g_strrstr (input, ".");

    if (arch_sep == NULL || (arch_sep + 1) == NULL) {
        ret = FALSE;
        goto out;
    }
    
    *arch_out = g_strdup (arch_sep + 1);
    arch_sep[0] = '\0';
    
    release_sep = g_strrstr (input, "-");

    if (release_sep == NULL || (release_sep + 1) == NULL) {
        ret = FALSE;
        goto out;
    }
    
    *release_out = g_strdup (release_sep + 1);
    release_sep[0] = '\0';

    ver_sep = g_strrstr (input, "-");

    if (ver_sep == NULL || (ver_sep + 1) == NULL) {
        ret = FALSE;
        goto out;
    }
    
    *version_out = g_strdup (ver_sep + 1);
    ver_sep[0] = '\0';

    epoch_sep = strstr (input, ":");

    if (epoch_sep == NULL || (epoch_sep + 1) == NULL) {
        ret = FALSE;
        goto out;
    }
    
    epoch_str = g_strndup (input, epoch_sep - input);
    *epoch_out = atoi (epoch_str);
    g_free (epoch_str);

    *name_out = g_strdup (epoch_sep + 1);

 out:
    g_free (input);

    return ret;
}

static RCPackage *
get_installed_package (const char *name, guint8 epoch,
                       const char *version, const char *release,
                       const char *arch)
{
    RCPackageDep *constraint;
    RCPackage *package;
    RCChannel *channel;

    channel = rc_world_get_channel_by_alias (rc_get_world (),
                                             "@system");

    g_return_val_if_fail (channel != NULL, FALSE);

    /* yum sucks and it apparently equates epoch == 0 to 'no epoch' */
    constraint = rc_package_dep_new (name, epoch == 0 ? FALSE : TRUE,
                                     epoch, version, release,
                                     RC_RELATION_EQUAL,
                                     channel,
                                     FALSE, FALSE);

    package = rc_world_get_package_with_constraint (rc_channel_get_world (channel),
                                                    RC_CHANNEL_SYSTEM,
                                                    name,
                                                    constraint, FALSE);

    rc_package_dep_unref (constraint);

    /* arch isn't in the constraint */
    if (package && package->arch !=
        rc_arch_from_string (arch))
        return NULL;
    
    return package;
}

gint
rcd_extract_packages_from_yum_buffer (RCDWorldRemote *world,
                                      const guint8 *orig_data, int len,
                                      RCPackman *packman,
                                      RCChannel *channel,
                                      RCPackageFn callback,
                                      gpointer user_data)
{
    int count = 0;
    char **lines;
    int i;
    char *data;

    g_return_val_if_fail (packman != NULL, -1);

    /* the yum header.info files are text files with header file names and urls
     *
     * example:
     * 0:pwlib-devel-1.5.0-4.i386=pwlib-devel-1.5.0-4.i386.rpm
     */

    data = g_strndup (orig_data, len);
    lines = g_strsplit (g_strstrip (data), "\n", 0);

    for (i = 0; lines[i]; i++) {
        char *line = lines[i];
        char **split_a;
        guint32 epoch = 0;
        char *name, *version, *release, *arch;
        char *rpm_url, *header_url;
        RCDCacheEntry *entry;
        RCDTransfer *transfer;
        const GByteArray *header_data;
        RCPackage *p;
        GByteArray *decompressed_data = NULL;
        RCPackage *existing_package;
        
        split_a = g_strsplit (line, "=", 2);

        g_assert (split_a[0] != NULL);
        g_assert (split_a[1] != NULL);
        
        if (!parse_nevra (split_a[0], &name, &epoch, &version,
                          &release, &arch)) {
            g_strfreev (split_a);
            continue;
        }

        existing_package = get_installed_package (name, epoch, version,
                                                  release, arch);

        if (existing_package == NULL) {
            header_url = g_strdup_printf ("%s/headers/%s-%d-%s-%s.%s.hdr",
                                          rc_channel_get_path (channel),
                                          name, epoch, version, release, arch);

            g_free (name);
            g_free (version);
            g_free (release);
            g_free (arch);

            entry = rcd_cache_lookup_by_url (rcd_cache_get_normal_cache (),
                                             header_url,
                                             TRUE);
        
            transfer = rcd_transfer_new (header_url,
                                         RCD_TRANSFER_FLAGS_NONE, entry);

            header_data = rcd_transfer_begin_blocking (transfer);

            if (rc_memory_looks_compressed (header_data->data, header_data->len)) {
                if (rc_uncompress_memory (header_data->data, header_data->len,
                                          &decompressed_data) < 0) {
                    g_strfreev (split_a);
                    continue;
                }

                header_data = decompressed_data;
            }

            rpm_url = g_strdup_printf ("%s/%s",
                                       rc_channel_get_file_path (channel),
                                       split_a[1]);
        
            p = rc_extract_yum_package (header_data->data, header_data->len,
                                        packman, rpm_url);
        } else {
            p = rc_package_copy (existing_package);
        }
        
        p->channel = rc_channel_ref (channel);

        g_strfreev (split_a);

        if (callback)
            callback (p, user_data);

        if (decompressed_data)
            g_byte_array_free (decompressed_data, TRUE);
        
        count++;
    }

    g_free (data);
    g_strfreev (lines);
    return count;
}


static gboolean
rcd_world_remote_parse_channel_data (RCDWorldRemote *remote,
                                     RCChannel      *channel,
                                     const guint8   *buffer,
                                     gint            buffer_len)
{
    GByteArray *decompressed_data = NULL;
    GSList *package_list = NULL;
    GSList *compat_arch_list, *package_iter;
    GTimer *timer;
    int count;

    if (rc_memory_looks_compressed (buffer, buffer_len)) {
        if (rc_uncompress_memory (buffer, buffer_len, &decompressed_data) < 0)
            return FALSE;

        buffer = decompressed_data->data;
        buffer_len = decompressed_data->len;
    }

    timer = g_timer_new ();
    g_timer_start (timer);

    switch (rc_channel_get_type (channel)) {
    case RC_CHANNEL_TYPE_HELIX:
        count = rc_extract_packages_from_helix_buffer (buffer, buffer_len,
                                                       channel,
                                                       prepend_package,
                                                       &package_list);
        break;

    case RC_CHANNEL_TYPE_DEBIAN:
        count = rc_extract_packages_from_debian_buffer (buffer, buffer_len,
                                                        channel,
                                                        prepend_package,
                                                        &package_list);
        break;

    case RC_CHANNEL_TYPE_APTRPM:
        count = rc_extract_packages_from_aptrpm_buffer (buffer, buffer_len,
                                                        rc_packman_get_global (),
                                                        channel,
                                                        prepend_package,
                                                        &package_list);
        break;
    case RC_CHANNEL_TYPE_YUM:
        count = rcd_extract_packages_from_yum_buffer (remote, buffer, buffer_len,
                                                      rc_packman_get_global (),
                                                      channel,
                                                      prepend_package,
                                                      &package_list);
        break;

    default:
        rc_debug (RC_DEBUG_LEVEL_WARNING, "Unknown channel type for '%s'!",
                  rc_channel_get_id (channel));
        count = -1;
        break;
    }

    if (decompressed_data)
        g_byte_array_free (decompressed_data, TRUE);

    if (count < 0) {
        rc_debug (RC_DEBUG_LEVEL_WARNING, "Unable to load packages in '%s'",
                  rc_channel_get_id (channel));
        g_timer_destroy (timer);
        return FALSE;
    }

    /* Sort the packages so that they can get inserted quickly into
     * the RCWorldStore
     */
    compat_arch_list =
        rc_arch_get_compat_list (rc_arch_get_system_arch ());

    package_list = g_slist_sort_with_data (package_list,
                                           compare_package_for_store,
                                           compat_arch_list);
    g_slist_free (compat_arch_list);

    for (package_iter = package_list;
         package_iter != NULL;
         package_iter = package_iter->next)
    {
        RCPackage *package = (RCPackage *) package_iter->data;
        rc_world_store_add_package (RC_WORLD_STORE (remote), package);
    }
    
    rc_package_slist_unref (package_list);
    g_timer_stop (timer);

    rc_debug (RC_DEBUG_LEVEL_MESSAGE,
              "Loaded %d packages in '%s' (%4.5f seconds)",
              count, rc_channel_get_id (channel),
              g_timer_elapsed (timer, NULL));

    g_timer_destroy (timer);

    return TRUE;
}

typedef struct {
    RCDWorldRemote *remote;
    RCChannel *channel;
} PerChannelData;

static void
channel_data_file_done_cb (RCDTransfer *t, gpointer user_data)
{
    PerChannelData *data = user_data;
    RCChannel *old_chan;
    
    if (!rcd_transfer_get_error (t)) {
        if (!t->cache_hit ||
            !rc_world_contains_channel (RC_WORLD (data->remote),
                                        data->channel)) {
            /* something changed, remove the old channel and add the new one */
            old_chan = rc_world_get_channel_by_name (RC_WORLD (data->remote),
                                                     rc_channel_get_name (data->channel));
            if (old_chan != NULL) {
                rc_world_store_remove_channel (RC_WORLD_STORE (data->remote),
                                               old_chan);
            }

            rc_world_store_add_channel (RC_WORLD_STORE (data->remote),
                                            data->channel);

            rcd_world_remote_parse_channel_data (data->remote,
                                                 data->channel,
                                                 t->data->data,
                                                 t->data->len);
        }
    }

    g_object_unref (data->remote);
    rc_channel_unref (data->channel);
    g_free (data);
}

typedef struct {
    RCDWorldRemote *remote;
    gboolean local;
    gboolean flush;
    RCDTransferPool *pool;
    GSList *channels;
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

    channel_data->channels = g_slist_prepend (channel_data->channels,
                                              channel);
            
    
    /* Channel data */
    if (channel_data->flush) {
        entry  = rcd_cache_lookup (rcd_cache_get_normal_cache (),
                                   "channel_data", rc_channel_get_id (channel),
                                   FALSE);

        if (entry)
            rcd_cache_entry_invalidate (entry);
    }

    entry = rcd_cache_lookup (rcd_cache_get_normal_cache (),
                              "channel_data", rc_channel_get_id (channel),
                              TRUE);

    need_download = TRUE;

    if (channel_data->local) {
        RCBuffer *buf;

        buf = rcd_cache_entry_map_file (entry);

        if (buf) {
            gboolean success;
            RCChannel *old_chan = rc_world_get_channel_by_name (RC_WORLD (channel_data->remote),
                                                                rc_channel_get_name (channel));

            /* remove the old channel and add the new one */
            rc_world_store_remove_channel (RC_WORLD_STORE (channel_data->remote),
                                           old_chan);
            rc_world_store_add_channel (RC_WORLD_STORE (channel_data->remote),
                                        channel);
            
            success = rcd_world_remote_parse_channel_data (channel_data->remote,
                                                           channel,
                                                           buf->data,
                                                           buf->size);

            rc_buffer_unmap_file (buf);

            need_download = !success;
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
    if (channel_data->flush) {
        entry  = rcd_cache_lookup (rcd_cache_get_normal_cache (),
                                   "icon", rc_channel_get_id (channel),
                                   FALSE);

        if (entry)
            rcd_cache_entry_invalidate (entry);
    }

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
                rcd_transfer_pool_new (FALSE, "Package icon download");
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
saved_target_differs (RCDWorldRemote *remote)
{
    RCDCacheEntry *entry;
    RCBuffer *buf;
    const char *target;

    entry = rcd_cache_lookup (rcd_cache_get_normal_cache (),
                              "distro_target",
                              RC_WORLD_SERVICE (remote)->unique_id,
                              FALSE);

    /* It hasn't been saved to disk yet.  Better safe than sorry */
    if (!entry)
        return TRUE;

    buf = rcd_cache_entry_map_file (entry);

    if (!buf || !buf->data)
        return TRUE;

    target = rc_distro_get_target (remote->distro);

    if (strlen (target) != buf->size)
        return TRUE;

    return strncmp (target, buf->data, buf->size);
}

static void
save_target (RCDWorldRemote *remote)
{
    RCDCacheEntry *entry;
    const char *target;

    target = rc_distro_get_target (remote->distro);

    entry = rcd_cache_lookup (rcd_cache_get_normal_cache (),
                              "distro_target",
                              RC_WORLD_SERVICE (remote)->unique_id,
                              TRUE);

    rcd_cache_entry_open (entry);

    if (rcd_cache_entry_is_open (entry)) {
        rcd_cache_entry_append (entry, target, strlen (target));
        rcd_cache_entry_close (entry);
    }
}

static gboolean
world_check_channel_cb (RCChannel *channel, gpointer user_data)
{
    GList *channels = user_data;
    GList *l;

    for (l = channels; l; l = l->next) {
        RCChannel *c = (RCChannel *)l->data;
        if (rc_channel_equal (c, channel))
            return TRUE;
    }

    rc_world_store_remove_channel (RC_WORLD_STORE (rc_channel_get_world (channel)),
                                   channel);
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
    const guint8 *buffer = NULL;
    gsize buffer_len = 0;

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

    if (!buffer) {
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

    g_assert (buffer != NULL);

    channel_data.remote = remote;
    channel_data.local = local;
    channel_data.flush = FALSE;
    channel_data.pool = NULL; /* May be set in _per_channel_cb() */
    channel_data.channels = NULL; /* also set in _per_channel_cb() */
    
    /*
     * Channel data is cached by service id + channel bid.  Channel bids
     * are the same across distros, so it's possible that your target can
     * change underneat you (like if you upgrade your distro), but you can
     * still get old channel data for your old target because it's not
     * newer than the last refresh you did on the old target.  This checks
     * to see if the previously saved target is different than our current
     * target and instructs rcd_world_remote_per_channel_cb() to flush the
     * old cached entries.
     */
    if (saved_target_differs (remote)) {
        rc_debug (RC_DEBUG_LEVEL_INFO,
                  "Distro target differs from last run on service '%s' [%s].  "
                  "Flushing channel data cache",
                  RC_WORLD_SERVICE (remote)->name,
                  RC_WORLD_SERVICE (remote)->unique_id);
        
        channel_data.local = FALSE;
        channel_data.flush = TRUE;

        save_target (remote);
    }

    N = rc_extract_channels_from_helix_buffer (buffer, buffer_len,
                                               rcd_world_remote_per_channel_cb,
                                               &channel_data);

    rc_debug (RC_DEBUG_LEVEL_DEBUG, "Got %d channels (all targets)", N);

    rc_world_foreach_channel (RC_WORLD (remote),
                              world_check_channel_cb,
                              channel_data.channels);
    g_slist_free (channel_data.channels);
    
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

    if (rc_world_is_refreshing (RC_WORLD (remote)) && pending != NULL) {
        g_signal_connect (pending, "complete",
                          (GCallback) pending_complete_cb,
                          g_object_ref (remote));
    }

cleanup:
    if (buf)
        rc_buffer_unmap_file (buf);

    if (t)
        g_object_unref (t);

    return pending;
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

    if (remote->channels_url) {
        pending = rcd_world_remote_fetch_channels (remote, local, &tmp_error);
    }
        
    if (tmp_error) {
        g_error_free (tmp_error);
        return NULL;
    }

    if (remote->mirrors_url)
        rcd_world_remote_fetch_mirrors (remote, local);

    if (remote->licenses_url)
        rcd_world_remote_fetch_licenses (remote, local);

    if (remote->news_url)
        rcd_world_remote_fetch_news (remote, local);

    return pending;
}

static RCPending *
rcd_world_remote_fetch (RCDWorldRemote *remote, gboolean local, GError **error)
{
    char *url;
    char *cache_entry_str = NULL;
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

            if (tmp_error == NULL) {
                g_free (cache_entry_str);

                return pending;
            } else {
                g_error_free (tmp_error);
                tmp_error = NULL;

                /* 
                 * The data is bad on disk, so let's invalidate the
                 * cache entry so we download it again
                 */
                rcd_cache_entry_invalidate (entry);
                
                entry = rcd_cache_lookup (rcd_cache_get_normal_cache (),
                                          "service_info", cache_entry_str,
                                          TRUE);
            }
        }
    }

    g_free (cache_entry_str);

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
