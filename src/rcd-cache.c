/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * rcd-cache.c: Caching of channel info
 *
 * Copyright (c) 2000-2002 Ximian, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

#include <errno.h>

typedef char *(*RCDCacheFilenameFunc) (RCDCache *cache, const char *url);

struct _RCDCache {
    GHashTable *entries;

    RCDCacheFilenameFunc filename_func;
};

struct _RCDCacheEntry {
    char *url;
    char *local_file;

    gboolean complete;

    int fd;

    char *entity_tag;
    char *last_modified;
};

static void
rcd_cache_entry_free (RCDCacheEntry *entry)
{
    g_free (entry->url);
    g_free (entry->local_file);
    g_free (entry->entity_tag);
    g_free (entry->last_modified);
    g_free (entry);
} /* rcd_cache_entry_free */

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
    char *tmp_fn;

    rc_close (entry->fd);

    tmp_fn = g_strdup_printf("%s.tmp", entry->local_file);
    rename(tmp_fn, entry->local_file);
    g_free(tmp_fn);
} /* rcd_cache_entry_close */

void
rcd_cache_entry_cancel (RCDCacheEntry *entry)
{
    rc_close (entry->fd);
} /* rcd_cache_entry_cancel */

void
rcd_cache_entry_append (RCDCacheEntry *entry, const char *data, gsize size)
{
    rc_write (entry->fd, data, size);
} /* rcd_cache_entry_append */

void
rcd_cache_entry_open (RCDCacheEntry *entry)
{
    char *cache_dir;
    char *tmp_fn;

    cache_dir = g_path_get_dirname (entry->local_file);
    if (!g_file_test (cache_dir, G_FILE_TEST_EXISTS)) {
        rc_mkdir (cache_dir, 0755);
    }
    g_free (cache_dir);

    tmp_fn = g_strconcat (entry->local_file, ".tmp", NULL);
    entry->fd = open (tmp_fn, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    if (entry->fd < 0) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Couldn't open %s for writing", tmp_fn);
        g_free (tmp_fn);

        return;
    }

    g_free (tmp_fn);
} /* rcd_cache_entry_open */

RCDCacheEntry *
rcd_cache_entry_new (RCDCache *cache, const char *url)
{
    RCDCacheEntry *entry;

    g_return_val_if_fail (cache, NULL);
    g_return_val_if_fail (url, NULL);

    if ((entry = g_hash_table_lookup (cache->entries, url))) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Cache entry already exists for %s", url);
        return entry;
    }

    entry = g_new0 (RCDCacheEntry, 1);
    
    entry->url = g_strdup (url);
    entry->local_file = rcd_cache_get_local_filename (cache, url);

    g_hash_table_insert (cache->entries, entry->url, entry);

    return entry;
} /* rcd_cache_entry_new */

RCDCacheEntry *
rcd_cache_lookup (RCDCache *cache, const char *url)
{
    RCDCacheEntry *entry;

    g_return_val_if_fail (cache, NULL);
    g_return_val_if_fail (url, NULL);

    entry = g_hash_table_lookup (cache->entries, url);

    if (!entry)
        return NULL;

    if (!g_file_test (entry->local_file, G_FILE_TEST_EXISTS)) {
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
    cache->entries = g_hash_table_new (g_str_hash, g_str_equal);
    cache->filename_func = filename_func;

    return cache;
} /* rcd_cache_new */

static char *
normal_cache_filename_func (RCDCache *cache, const char *url)
{
    SoupUri *uri = soup_uri_new (url);
    const char *filename;

    filename = uri->path;

    if (*filename == '/')
        filename++;

    if (!*filename)
        filename = "index";

    return g_strdup_printf ("%s:%d/%s", uri->host, uri->port,
                            g_strdelimit (g_strdup (filename), "/", '-'));
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

RCDCache *
rcd_cache_get_normal_cache (void)
{
    static RCDCache *cache = NULL;

    if (cache == NULL) {
        cache = rcd_cache_new (normal_cache_filename_func);
    }

    return cache;
} /* rcd_cache_get_normal_cache */

RCDCache *
rcd_cache_get_package_cache (void)
{
    static RCDCache *cache = NULL;

    if (cache == NULL) {
        cache = rcd_cache_new (package_cache_filename_func);
    }

    return cache;
} /* rcd_cache_get_package_cache */
