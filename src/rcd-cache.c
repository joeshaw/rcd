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

/* Generic interface stuff here */
typedef char *(*RCDCacheMungeFunc)(RCDCache *cache, const char *filename);

struct _RCDCache {
    const char *path;

    GHashTable *handles;

    RCDCacheMungeFunc munge_func;

    gpointer user_data;
};

void
rcd_cache_set_user_data(RCDCache *cache, gpointer user_data)
{
    g_return_if_fail(cache);

    cache->user_data = user_data;
} /* rcd_cache_set_user_data */

gpointer
rcd_cache_get_user_data(RCDCache *cache)
{
    g_return_val_if_fail(cache, NULL);

    return cache->user_data;
} /* rcd_cache_get_user_data */

char *
rcd_cache_get_cache_directory(RCDCache *cache)
{
    const char *cache_dir;
    char *dir;

    cache_dir = rcd_prefs_get_cache_dir ();

    if (!cache_dir)
        return NULL;
    
    if (cache->path) {
        dir = g_strdup_printf("%s/%s", cache_dir, cache->path);
    }
    else
        dir = g_strdup(cache_dir);

    return dir;
} /* rcd_cache_get_cache_directory */

char *
rcd_cache_get_cache_filename(RCDCache *cache, const char *filename)
{
    char *munged;
    const char *cache_dir;
    char *cache_fn;

    if (cache->munge_func)
        munged = cache->munge_func(cache, filename);
    else
        munged = NULL;

    cache_dir = rcd_prefs_get_cache_dir ();

    if (cache->path) {
        cache_fn = g_strdup_printf(
            "%s/%s/%s", cache_dir, cache->path, munged ? munged : filename);
    }
    else {
        cache_fn = g_strdup_printf(
            "%s/%s", cache_dir, munged ? munged : filename);
    }

    g_free(munged);
    
    return cache_fn;
} /* rcd_cache_get_cache_filename */

const char *
rcd_cache_get_modification_time(RCDCache *cache, const char *filename)
{
    char *cache_fn;
    struct stat st;
    struct tm *tm;
    static char *time_string = NULL;

    g_return_val_if_fail(cache, NULL);
    g_return_val_if_fail(filename, NULL);

    cache_fn = rcd_cache_get_cache_filename(cache, filename);

    if (!g_file_test(cache_fn, G_FILE_TEST_EXISTS))
        return NULL;

    stat(cache_fn, &st);
    tm = gmtime(&st.st_mtime);

    if (!time_string)
        time_string = g_malloc(40);

    /* Create a time string that conforms to RFC 1123 */
    strftime(time_string, 40, "%a, %d %b %Y %H:%M:%S %z", tm);

    g_free(cache_fn);

    return time_string;
} /* rcd_cache_get_modification_time */

gboolean
rcd_cache_is_active(RCDCache *cache, const char *filename)
{
    return (g_hash_table_lookup(cache->handles, filename) != NULL);
} /* rcd_cache_is_active */

void
rcd_cache_open(RCDCache *cache, const char *filename, gboolean append)
{
    char *cache_dir;
    char *cache_fn;
    char *tmp_fn;
    int flags;
    int fd;

    cache_dir = rcd_cache_get_cache_directory(cache);

    g_return_if_fail(cache_dir);

    if (!g_file_test(cache_dir, G_FILE_TEST_EXISTS)) {
        rc_mkdir(cache_dir, 0755);
    }
    g_free(cache_dir);

    cache_fn = rcd_cache_get_cache_filename(cache, filename);
    tmp_fn = g_strdup_printf("%s.tmp", cache_fn);
    
    flags = O_WRONLY | O_CREAT;
    if (append)
        flags |= O_APPEND;
    else
        flags |= O_TRUNC;

    fd = open(tmp_fn, flags, 0644);

    if (fd < 0) {
        g_warning("Couldn't open %s (%s) for writing", cache_fn, filename);
        goto finished;
    }

    g_hash_table_insert(
        cache->handles, g_strdup(filename), GINT_TO_POINTER(fd));

 finished:
    g_free(cache_fn);
    g_free(tmp_fn);

} /* rcd_cache_open */

void
rcd_cache_append(RCDCache *cache, const char *filename, 
                 const char *data, guint32 size)
{
    gpointer handle;
    int fd;

    handle = g_hash_table_lookup(cache->handles, filename);

    if (!handle) {
        g_warning("Couldn't find %s in active cache", filename);
        return;
    }

    fd = GPOINTER_TO_INT(handle);

    rc_write(fd, data, size);
} /* rcd_cache_append */

static void
cache_close(RCDCache *cache, const char *filename)
{
    gpointer handle;
    gpointer filename_copy;
    int fd;

    if (!g_hash_table_lookup_extended(
            cache->handles, filename, &filename_copy, &handle)) {
        g_warning("Couldn't find %s in active cache", filename);
        return;
    }

    fd = GPOINTER_TO_INT(handle);
    rc_close(fd);

    g_hash_table_remove(cache->handles, filename);
    g_free(filename_copy);
} /* cache_close */

void
rcd_cache_close(RCDCache *cache, const char *filename)
{
    char *cache_fn;
    char *tmp_fn;

    cache_close(cache, filename);

    cache_fn = rcd_cache_get_cache_filename(cache, filename);
    tmp_fn = g_strdup_printf("%s.tmp", cache_fn);
    rename(tmp_fn, cache_fn);
    g_free(cache_fn);
    g_free(tmp_fn);
} /* rcd_cache_close */

void
rcd_cache_invalidate(RCDCache *cache, const char *filename)
{
    char *cache_fn;

    if (rcd_cache_is_active(cache, filename))
        cache_close(cache, filename);

    cache_fn = rcd_cache_get_cache_filename(cache, filename);
    unlink(cache_fn);
    g_free(cache_fn);
} /* rcd_cache_invalidate */

void
rcd_cache_invalidate_all(RCDCache *cache)
{
    char *cache_dir;

    cache_dir = rcd_cache_get_cache_directory(cache);

    if (!cache_dir)
        return;

    rc_rmdir(cache_dir);
    g_free(cache_dir);
} /* rcd_cache_invalidate_all */

void
rcd_cache_invalidate_all_older(RCDCache *cache, time_t seconds)
{
    char *cache_dir;
    DIR *dir;
    time_t now;
    struct dirent *dir_entry;

    cache_dir = rcd_cache_get_cache_directory(cache);

    if (!cache_dir)
        return;

    dir = opendir(cache_dir);
    g_return_if_fail(dir);

    now = time(NULL);

    while ((dir_entry = readdir(dir))) {
        char *filename;
        struct stat s;

        filename = g_strdup_printf("%s/%s", cache_dir, dir_entry->d_name);

        stat(filename, &s);

        if (s.st_mtime + seconds < now) {
            rc_debug(
                RC_DEBUG_LEVEL_DEBUG, "Deleting from cache: %s\n", filename);
            unlink(filename);
        }

        g_free(filename);
    }

    closedir(dir);
    g_free(cache_dir);
} /* rcd_cache_invalidate_all_older */

static RCDCache *
rcd_cache_new(const char *path, RCDCacheMungeFunc munge_func)
{
    RCDCache *cache;

    cache = g_new0(RCDCache, 1);

    cache->path = path;
    cache->munge_func = munge_func;

    cache->handles = g_hash_table_new(g_str_hash, g_str_equal);

    return cache;
} /* rcd_cache_new */

/* Actual implementation of RC's caches below here. */
static char *
munge_filename(RCDCache *cache, const char *filename)
{
    if (*filename == '/')
        filename++;

    if (!*filename)
        return g_strdup("index");
    
    return g_strdelimit(g_strdup(filename), "/", '-');
} /* munge_filename */

static char *
munge_package(RCDCache *cache, const char *filename)
{
    char *munge;

    munge = strrchr(filename, '/');

    if (munge)
        return g_strdup(munge + 1);
    else
        return g_strdup(filename);
} /* munge_package */

static char *
munge_icon(RCDCache *cache, const char *filename)
{
    int channel_id;
    char *extension;
    char *munge;

    channel_id = GPOINTER_TO_INT(rcd_cache_get_user_data(cache));
    
    extension = strrchr(filename, '.');

    munge = g_strdup_printf(
        "channel-%d%s", channel_id, extension ? extension : "");

    return munge;
} /* munge_icon */

RCDCache *
rcd_cache_get_package_cache (void)
{
    static RCDCache *cache = NULL;

    if (cache == NULL) {
        cache = rcd_cache_new ("packages", munge_package);
    }

    return cache;
}

RCDCache *
rcd_cache_get_icon_cache (void)
{
    static RCDCache *cache = NULL;

    if (cache == NULL) {
        cache = rcd_cache_new ("icons", munge_icon);
    }

    return cache;
}

RCDCache *
rcd_cache_get_normal_cache (void)
{
    static RCDCache *cache = NULL;

    if (cache == NULL) {
        const char *url = rcd_prefs_get_host ();
        SoupUri *uri = soup_uri_new(url);
        char *normal_path;

        /* Assert that rc_rcd_get_host() must always return a valid URI */
        g_assert(uri);

        normal_path = g_strdup_printf("%s:%d", uri->host, uri->port);

        soup_uri_free(uri);

        cache = rcd_cache_new (normal_path, munge_filename);
    }

    return cache;
}

