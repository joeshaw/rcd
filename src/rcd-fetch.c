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
#include "rcd-rpc-util.h"
#include "rcd-transaction.h"
#include "rcd-transfer.h"
#include "rcd-transfer-http.h"
#include "rcd-transfer-pool.h"
#include "rcd-world-remote.h"

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

static xmlrpc_value *
fetch_register_build_args (xmlrpc_env *env,
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

    value = xmlrpc_build_value(env, "()");
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
	xmlrpc_array_append_item (env, value,
			xmlrpc_build_value(env, "s", activation_code));
        XMLRPC_FAIL_IF_FAULT (env);
    }
 
    if (email) {
	xmlrpc_array_append_item (env, value,
			xmlrpc_build_value(env, "s", email));
        XMLRPC_FAIL_IF_FAULT (env);
    }

    xmlrpc_array_append_item(env, value,
		    	xmlrpc_build_value(env, "s", hostname));
 
    if (alias) {
	xmlrpc_array_append_item (env, value,
			xmlrpc_build_value(env, "s", alias));
        XMLRPC_FAIL_IF_FAULT (env);
    }
 
cleanup:
    if (env->fault_occurred) {
        xmlrpc_DECREF (value);
        value = NULL;
    }
 
    return value;
}

static gboolean
register_cb (RCWorld *world, gpointer user_data)
{
    RCDWorldRemote *remote = RCD_WORLD_REMOTE (world);
    xmlrpc_value *value = user_data;
    xmlrpc_env env;
    xmlrpc_server_info *server = NULL;

    xmlrpc_env_init (&env);

    server = rcd_xmlrpc_get_server (&env, remote->activation_root_url);
    XMLRPC_FAIL_IF_FAULT (&env);

    xmlrpc_server_info_set_auth (&env, server,
                                 rcd_prefs_get_mid (),
                                 rcd_prefs_get_secret ());
    XMLRPC_FAIL_IF_FAULT (&env);

    /* FIXME: Return value */
    xmlrpc_client_call_server_params (&env, server,
                                      "rcserver.activate", value);
 
cleanup:
    if (env.fault_occurred) {
        rc_debug (RC_DEBUG_LEVEL_WARNING, "Unable to activate with '%s': %s",
                  remote->activation_root_url, env.fault_string);
    }

    xmlrpc_env_clean (&env);
    
    if (server)
        xmlrpc_server_info_free (server);
 
    return TRUE;
}
 
xmlrpc_value *
rcd_fetch_register (xmlrpc_env *opt_env,
                    const char *activation_code,
                    const char *email,
                    const char *alias)
{
    xmlrpc_env env;
    xmlrpc_value *retval = NULL;
    xmlrpc_value *value = NULL;

    if (!opt_env)
        xmlrpc_env_init (&env);
    else
        env = *opt_env;

    value = fetch_register_build_args (&env, activation_code, email, alias);
    XMLRPC_FAIL_IF_FAULT (&env);

    rc_world_multi_foreach_subworld_by_type (RC_WORLD_MULTI (rc_get_world ()),
                                             RCD_TYPE_WORLD_REMOTE,
                                             register_cb, value);
cleanup:
    if (env.fault_occurred)
        retval = NULL;
    else
        retval = xmlrpc_build_value (&env, "()"); /* FIXME? */

    if (!opt_env)
        xmlrpc_env_clean (&env);

    if (value)
        xmlrpc_DECREF (value);

    return retval;
}

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
