/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-cache.c: Caching of channel info
 *
 * Copyright (c) 2000-2002 Ximian, Inc.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 */

#include <config.h>
#include "rcd-cache.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>

#include <libredcarpet.h>
#include <libsoup/soup-uri.h>

#include "rcd-prefs.h"
#include "rcd-expire.h"
#include "rcd-shutdown.h"

#include <errno.h>

typedef char *(*RCDCacheFilenameFunc) (RCDCache *cache, const char *url);

struct _RCDCache {
    GHashTable *entries;

    RCDCacheFilenameFunc filename_func;

    gpointer user_data;
};

struct _RCDCacheEntry {
    RCDCache *cache;

    char *url;
    char *local_file;
    char *tmp_file;

    int fd;

    char *entity_tag;
    char *last_modified;
};

static void
rcd_cache_entry_free (RCDCacheEntry *entry)
{
    g_free (entry->url);
    g_free (entry->local_file);
    g_free (entry->tmp_file);
    g_free (entry->entity_tag);
    g_free (entry->last_modified);
    g_free (entry);
} /* rcd_cache_entry_ref */

char *
rcd_cache_get_local_filename (RCDCache *cache, const char *url)
{
    char *cache_fn;
    char *local_filename;

    cache_fn = cache->filename_func (cache, url);

    local_filename = g_strconcat (rcd_prefs_get_cache_dir (), "/", cache_fn, NULL);

    g_free (cache_fn);

    return local_filename;
} /* rcd_cache_get_local_filename */

char *
rcd_cache_entry_get_local_filename (RCDCacheEntry *entry)
{
    return g_strdup (entry->local_file);
} /* rcd_cache_entry_get_local_filename */

const char *
rcd_cache_entry_get_modification_time (RCDCacheEntry *entry)
{
    struct stat st;
    struct tm *tm;
    static char *time_string = NULL;

    if (entry->last_modified)
        return entry->last_modified;

    /* This is less than exact, but is better than nothing at all. */
    if (!g_file_test (entry->local_file, G_FILE_TEST_EXISTS))
        return NULL;

    stat (entry->local_file, &st);
    tm = gmtime (&st.st_mtime);

    if (!time_string)
        time_string = g_malloc (40);

    /* Create a time string that conforms to RFC 1123 */
    strftime(time_string, 40, "%a, %d %b %Y %H:%M:%S %z", tm);

    return time_string;
} /* rcd_cache_entry_get_modification_time */

const char *
rcd_cache_entry_get_entity_tag (RCDCacheEntry *entry)
{
    return entry->entity_tag;
} /* rcd_cache_entry_get_entity_tag */

void
rcd_cache_entry_set_modification_time (RCDCacheEntry *entry, const char *modtime)
{
    entry->last_modified = g_strdup (modtime);
} /* rcd_cache_entry_set_modification_time */

void
rcd_cache_entry_set_entity_tag (RCDCacheEntry *entry, const char *etag)
{
    entry->entity_tag = g_strdup (etag);
} /* rcd_cache_entry_set_entity_tag */

void
rcd_cache_entry_close (RCDCacheEntry *entry)
{
    rc_close (entry->fd);
    rename (entry->tmp_file, entry->local_file);

    g_free (entry->tmp_file);
    entry->tmp_file = NULL;

    g_hash_table_insert (entry->cache->entries,
                         g_strdup (entry->local_file), entry);
} /* rcd_cache_entry_close */

void
rcd_cache_entry_cancel (RCDCacheEntry *entry)
{
    if (entry->fd != -1)
        rc_close (entry->fd);
} /* rcd_cache_entry_cancel */

void
rcd_cache_entry_append (RCDCacheEntry *entry, const char *data, gsize size)
{
    g_return_if_fail (entry->fd != -1);

    rc_write (entry->fd, data, size);
} /* rcd_cache_entry_append */

void
rcd_cache_entry_open (RCDCacheEntry *entry)
{
    char *cache_dir;

    cache_dir = g_path_get_dirname (entry->local_file);
    if (!g_file_test (cache_dir, G_FILE_TEST_EXISTS)) {
        rc_mkdir (cache_dir, 0755);
    }
    g_free (cache_dir);

    entry->tmp_file = g_strconcat (entry->local_file, ".XXXXXX", NULL);
    entry->fd = g_mkstemp (entry->tmp_file);

    if (entry->fd < 0) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Couldn't open %s for writing", entry->tmp_file);

        return;
    }

    fchmod (entry->fd, 0644);
} /* rcd_cache_entry_open */

RCDCacheEntry *
rcd_cache_entry_new (RCDCache *cache, const char *url)
{
    RCDCacheEntry *entry;
    char *local_file;

    g_return_val_if_fail (cache, NULL);
    g_return_val_if_fail (url, NULL);

    local_file = rcd_cache_get_local_filename (cache, url);

    if ((entry = g_hash_table_lookup (cache->entries, local_file))) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Cache entry already exists for %s", local_file);
        g_free (local_file);
        return entry;
    }

    entry = g_new0 (RCDCacheEntry, 1);
    
    entry->cache = cache;
    entry->url = g_strdup (url);
    entry->local_file = local_file;
    entry->fd = -1;

    return entry;
} /* rcd_cache_entry_new */

void
rcd_cache_entry_invalidate (RCDCacheEntry *entry)
{
    g_return_if_fail (entry);

    g_hash_table_remove (entry->cache->entries, entry);
    rcd_cache_entry_free (entry);
} /* rcd_cache_entry_invalidate */

RCDCacheEntry *
rcd_cache_lookup (RCDCache *cache, const char *url)
{
    RCDCacheEntry *entry;
    char *local_file;

    g_return_val_if_fail (cache, NULL);
    g_return_val_if_fail (url, NULL);

    local_file = rcd_cache_get_local_filename (cache, url);
    entry = g_hash_table_lookup (cache->entries, local_file);
    g_free (local_file);

    if (!entry)
        return NULL;

    if (!g_file_test (entry->local_file, G_FILE_TEST_EXISTS)) {
        g_hash_table_remove (cache->entries, entry);
        rcd_cache_entry_free (entry);
        return NULL;
    }

    return entry;
} /* rcd_cache_lookup */

static RCDCache *
rcd_cache_new (RCDCacheFilenameFunc filename_func)
{
    RCDCache *cache;

    cache = g_new0 (RCDCache, 1);
    cache->entries = g_hash_table_new_full (g_str_hash, g_str_equal,
                                            g_free, NULL);
    cache->filename_func = filename_func;

    return cache;
} /* rcd_cache_new */

static char *
normal_cache_filename_func (RCDCache *cache, const char *url)
{
    SoupUri *uri = soup_uri_new (url);
    char *fn;
    char *filename;
    char *local_filename;

    if (uri->querystring)
        fn = g_strconcat (uri->path, "?", uri->querystring, NULL);
    else
        fn = g_strdup (uri->path);

    filename = fn;

    if (*filename == '/')
        filename++;

    if (!*filename)
        filename = "index";

    local_filename = g_strdup_printf (
        "%s:%d/%s", uri->host, uri->port,
        g_strdelimit (filename, "/", '-'));

    g_free (fn);
    soup_uri_free (uri);

    return local_filename;
} /* normal_cache_filename_func */

static char *
package_cache_filename_func (RCDCache *cache, const char *url)
{
    char *package_file;
    char *full_path;

    package_file = g_path_get_basename (url);
    full_path = g_strconcat ("packages/", package_file, NULL);
    g_free (package_file);

    return full_path;
} /* package_cache_filename_func */

static char *
icon_cache_filename_func (RCDCache *cache, const char *url)
{
    int channel_id = GPOINTER_TO_INT (cache->user_data);
    const char *extension;
    char *path;

    extension = strrchr (url, '.');
    path = g_strdup_printf ("icons/channel-%d%s", 
                            channel_id, extension ? extension : "");

    return path;
} /* icon_cache_filename_func */

RCDCache *
rcd_cache_get_normal_cache (void)
{
    static RCDCache *cache = NULL;

    if (cache == NULL) {
        cache = rcd_cache_new (normal_cache_filename_func);
    }

    return cache;
} /* rcd_cache_get_normal_cache */

static void
shutdown_expire_package_cache (gpointer user_data)
{
    rcd_cache_expire_package_cache ();
}

RCDCache *
rcd_cache_get_package_cache (void)
{
    static RCDCache *cache = NULL;

    if (cache == NULL) {
        cache = rcd_cache_new (package_cache_filename_func);

        rcd_shutdown_add_handler (shutdown_expire_package_cache,
                                  NULL);
    }

    return cache;
} /* rcd_cache_get_package_cache */

RCDCache *
rcd_cache_get_icon_cache (int channel_id)
{
    static RCDCache *cache = NULL;

    if (cache == NULL) {
        cache = rcd_cache_new (icon_cache_filename_func);
    }

    cache->user_data = GINT_TO_POINTER (channel_id);

    return cache;
} /* rcd_cache_get_icon_cache */

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

void
rcd_cache_expire (RCDCache *cache,
                  double    max_age_in_days,
                  double    max_size_in_mb)
{
    char *fake_path;
    char *cache_dirname;

    g_return_if_fail (cache != NULL);

    fake_path = rcd_cache_get_local_filename (cache, "foo");
    cache_dirname = g_path_get_dirname (fake_path);

    if (max_age_in_days > 0) {
        rcd_expire_by_age (cache_dirname,
                           NULL,
                           FALSE,
                           max_age_in_days);
    }

    if (max_size_in_mb > 0) {
        rcd_expire_by_size (cache_dirname,
                            NULL,
                            FALSE,
                            max_size_in_mb,
                            1.0); /* min age */
    }

    g_free (fake_path);
    g_free (cache_dirname);
}

void
rcd_cache_expire_package_cache (void)
{
    if (rcd_prefs_get_cache_cleanup_enabled ()) {

        rcd_cache_expire (rcd_cache_get_package_cache (),
                          rcd_prefs_get_cache_max_age_in_days (),
                          rcd_prefs_get_cache_max_size_in_mb ());
    }
}
