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
#include <ctype.h>

#include <libredcarpet.h>
#include <libsoup/soup-uri.h>

#include "rcd-prefs.h"
#include "rcd-expire.h"
#include "rcd-shutdown.h"
#include "rcd-transaction.h"

#include <errno.h>

typedef char *   (*RCDCacheBaseDirFunc)   (RCDCache *cache);
typedef char *   (*RCDCacheFilenameFunc)  (RCDCache *cache,
                                           const char *source_id,
                                           const char *file_tag);

typedef gboolean (*RCDCacheFileCheckFunc) (const char *filename);

struct _RCDCache {
    GHashTable *entries;

    RCDCacheBaseDirFunc   base_dir_func;
    RCDCacheFilenameFunc  filename_func;
    RCDCacheFileCheckFunc file_check_func;

    gpointer user_data;
};

struct _RCDCacheEntry {
    RCDCache *cache;

    char *source_id;
    char *file_tag;
    char *url;

    char *local_file;
    char *tmp_file;

    int fd;

    char *entity_tag;
    char *last_modified;
};

static char *rcd_cache_get_local_filename (RCDCache *cache,
                                           const char *source_id,
                                           const char *file_tag);

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static RCDCacheEntry *
rcd_cache_entry_new (RCDCache   *cache,
                     const char *source_id,
                     const char *file_tag)
{
    RCDCacheEntry *entry;

    g_return_val_if_fail (cache != NULL, NULL);
    g_return_val_if_fail (source_id != NULL, NULL);
    g_return_val_if_fail (file_tag != NULL, NULL);

    g_assert (cache->filename_func != NULL);

    entry = g_new0 (RCDCacheEntry, 1);
    
    entry->cache         = cache;
    entry->source_id     = g_strdup (source_id);
    entry->file_tag      = g_strdup (file_tag);
    entry->url           = NULL;
    entry->local_file    = rcd_cache_get_local_filename (cache,
                                                         source_id,
                                                         file_tag);
    entry->tmp_file      = NULL;
    entry->fd            = -1;
    entry->entity_tag    = NULL;
    entry->last_modified = NULL;

    return entry;
}

static RCDCacheEntry *
rcd_cache_entry_new_from_url (RCDCache   *cache,
                              const char *url)
{
    RCDCacheEntry *entry;
    char *source_id;
    char *file_tag;

    g_return_val_if_fail (cache != NULL, NULL);
    g_return_val_if_fail (url != NULL, NULL);

    source_id = g_path_get_dirname (url);
    file_tag  = g_path_get_basename (url);

    if (! strncmp (source_id, "http://", 7)) {
        char *tmp = g_strdup (source_id+7);
        g_free (source_id);
        source_id = tmp;
    } else if (! strncmp (source_id, "https://", 8)) {
        char *tmp = g_strdup_printf ("s:%s", source_id+8);
        g_free (source_id);
        source_id = tmp;
    }

    entry = rcd_cache_entry_new (cache, source_id, file_tag);
    entry->url = g_strdup (url);

    g_free (source_id);
    g_free (file_tag);

    return entry;
}

static void
rcd_cache_entry_free (RCDCacheEntry *entry)
{
    if (entry != NULL) {
        g_free (entry->source_id);
        g_free (entry->file_tag);
        g_free (entry->url);
        g_free (entry->local_file);
        g_free (entry->tmp_file);
        g_free (entry->entity_tag);
        g_free (entry->last_modified);
        g_free (entry);
    }
} /* rcd_cache_entry_free */

static gboolean
rcd_cache_entry_is_valid (RCDCacheEntry *entry)
{
    g_return_val_if_fail (entry != NULL, FALSE);

    if (! g_file_test (entry->local_file, G_FILE_TEST_EXISTS))
        return FALSE;

    if (entry->cache->file_check_func
        && ! entry->cache->file_check_func (entry->local_file))
        return FALSE;

    return TRUE;
}

void
rcd_cache_entry_open (RCDCacheEntry *entry)
{
    char *cache_dir;

    g_return_if_fail (entry != NULL);
    g_return_if_fail (entry->fd == -1);

    cache_dir = g_path_get_dirname (entry->local_file);

    if (!g_path_is_absolute (cache_dir)) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Cache directory '%s' is not absolute",
                  cache_dir);
        return;
    }

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

gboolean
rcd_cache_entry_is_open (RCDCacheEntry *entry)
{
    g_return_val_if_fail (entry != NULL, FALSE);

    return entry->fd != -1;
}

void
rcd_cache_entry_append (RCDCacheEntry *entry, const char *data, gsize size)
{
    g_return_if_fail (entry != NULL);
    g_return_if_fail (entry->fd != -1);
    g_return_if_fail (data != NULL || size == 0);

    if (size > 0)
        rc_write (entry->fd, data, size);
} /* rcd_cache_entry_append */

void
rcd_cache_entry_close (RCDCacheEntry *entry)
{
    g_return_if_fail (entry != NULL);
    g_return_if_fail (entry->fd != -1);

    rc_close (entry->fd);
    entry->fd = -1;

    rename (entry->tmp_file, entry->local_file);

    g_free (entry->tmp_file);
    entry->tmp_file = NULL;

    g_hash_table_insert (entry->cache->entries,
                         entry->local_file, entry);
} /* rcd_cache_entry_close */

void
rcd_cache_entry_cancel (RCDCacheEntry *entry)
{
    g_return_if_fail (entry != NULL);

    if (entry->fd != -1) {
        rc_close (entry->fd);
        entry->fd = -1;
    }
} /* rcd_cache_entry_cancel */

void
rcd_cache_entry_invalidate (RCDCacheEntry *entry)
{
    g_return_if_fail (entry);

    unlink (entry->local_file);
    g_hash_table_remove (entry->cache->entries, entry->local_file);
    rcd_cache_entry_free (entry);
} /* rcd_cache_entry_invalidate */

const char *
rcd_cache_entry_get_modification_time (RCDCacheEntry *entry)
{
    struct stat st;
    struct tm *tm;
    static char *time_string = NULL;

    g_return_val_if_fail (entry != NULL, NULL);

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
    strftime(time_string, 40, "%a, %d %b %Y %H:%M:%S %Z", tm);

    return time_string;
} /* rcd_cache_entry_get_modification_time */

const char *
rcd_cache_entry_get_entity_tag (RCDCacheEntry *entry)
{
    g_return_val_if_fail (entry != NULL, NULL);
    return entry->entity_tag;
} /* rcd_cache_entry_get_entity_tag */

void
rcd_cache_entry_set_modification_time (RCDCacheEntry *entry,
                                       const char    *modtime)
{
    g_return_if_fail (entry != NULL);
    g_return_if_fail (modtime != NULL);
    g_free (entry->last_modified);
    entry->last_modified = g_strdup (modtime);
} /* rcd_cache_entry_set_modification_time */

void
rcd_cache_entry_set_entity_tag (RCDCacheEntry *entry,
                                const char    *etag)
{
    g_return_if_fail (entry != NULL);
    g_return_if_fail (etag != NULL);
    g_free (entry->entity_tag);
    entry->entity_tag = g_strdup (etag);
} /* rcd_cache_entry_set_entity_tag */

char *
rcd_cache_entry_get_local_filename (RCDCacheEntry *entry)
{
    g_return_val_if_fail (entry != NULL, NULL);
    return g_strdup (entry->local_file);
} /* rcd_cache_entry_get_local_filename */

RCBuffer *
rcd_cache_entry_map_file (RCDCacheEntry *entry)
{
    RCBuffer *buf;
    g_return_val_if_fail (entry != NULL, NULL);

    if (! g_file_test (entry->local_file, G_FILE_TEST_EXISTS))
        return NULL;

    buf = rc_buffer_map_file (entry->local_file);

    return buf;
}


/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static RCDCache *
rcd_cache_new (RCDCacheBaseDirFunc   base_dir_func,
               RCDCacheFilenameFunc  filename_func,
               RCDCacheFileCheckFunc file_check_func)
{
    RCDCache *cache;

    cache = g_new0 (RCDCache, 1);

    cache->entries = g_hash_table_new (g_str_hash, g_str_equal);

    cache->base_dir_func   = base_dir_func;
    cache->filename_func   = filename_func;
    cache->file_check_func = file_check_func;

    return cache;
}

static char *
rcd_cache_get_base_dir (RCDCache *cache)
{
    g_return_val_if_fail (cache != NULL, NULL);
    g_assert (cache->base_dir_func != NULL);

    return cache->base_dir_func (cache);
}

static char *
rcd_cache_get_local_filename (RCDCache *cache,
                              const char *source_id,
                              const char *file_tag)
{
    char *base_dir;
    char *partial_filename;
    char *full_filename;

    g_return_val_if_fail (cache != NULL, NULL);
    g_return_val_if_fail (source_id != NULL, NULL);
    g_return_val_if_fail (file_tag != NULL, NULL);

    base_dir = rcd_cache_get_base_dir (cache);
    
    g_assert (cache->filename_func);
    partial_filename = cache->filename_func (cache, source_id, file_tag);

    full_filename = g_strconcat (base_dir, "/", partial_filename, NULL);
    
    g_free (base_dir);
    g_free (partial_filename);

    return full_filename;
}

static RCDCacheEntry *
rcd_cache_lookup_entry (RCDCache      *cache,
                        RCDCacheEntry *base_entry,
                        gboolean       add_base_on_cache_miss)
{
    RCDCacheEntry *entry;

    g_return_val_if_fail (cache != NULL, NULL);
    g_return_val_if_fail (base_entry != NULL, NULL);

    entry = g_hash_table_lookup (cache->entries, base_entry->local_file);
    if (entry) {
        if (rcd_cache_entry_is_valid (entry)) {
            rcd_cache_entry_free (base_entry);
            return entry;
        } else {
            rcd_cache_entry_invalidate (entry);
        }
    } else {
        /* If the file isn't in the cache and add_base_on_cache_miss
           is not set, just return NULL. */
        if (! rcd_cache_entry_is_valid (base_entry)
            && ! add_base_on_cache_miss) {
            rcd_cache_entry_free (base_entry);
            return NULL;
        }
    }

    g_hash_table_insert (cache->entries,
                         base_entry->local_file,
                         base_entry);

    return base_entry;
}

RCDCacheEntry *
rcd_cache_lookup (RCDCache   *cache,
                  const char *source_id,
                  const char *file_tag,
                  gboolean    create_new_if_nonexistent)
{
    RCDCacheEntry *entry;

    g_return_val_if_fail (cache != NULL, NULL);
    if (source_id == NULL)
        source_id = ".NULL.";
    if (file_tag == NULL)
        file_tag = ".NULL.";

    entry = rcd_cache_entry_new (cache, source_id, file_tag);
    entry = rcd_cache_lookup_entry (cache, entry, create_new_if_nonexistent);

    return entry;
}

RCDCacheEntry *
rcd_cache_lookup_by_url (RCDCache   *cache,
                         const char *url,
                         gboolean    create_new_if_nonexistent)
{
    RCDCacheEntry *entry;

    g_return_val_if_fail (cache != NULL, NULL);
    g_return_val_if_fail (url != NULL, NULL);

    entry = rcd_cache_entry_new_from_url (cache, url);
    entry = rcd_cache_lookup_entry (cache, entry, create_new_if_nonexistent);

    return entry;
}

void
rcd_cache_expire (RCDCache *cache,
                  double    max_age_in_days,
                  double    max_size_in_mb)
{
    char *cache_dirname;

    g_return_if_fail (cache != NULL);

    cache_dirname = rcd_cache_get_base_dir (cache);

    if (max_age_in_days > 0) {
        rcd_expire_by_age (cache_dirname,
                           NULL,
                           TRUE,
                           max_age_in_days);
    }

    if (max_size_in_mb > 0) {
        rcd_expire_by_size (cache_dirname,
                            NULL,
                            TRUE,
                            max_size_in_mb,
                            1.0); /* min age */
    }

    g_free (cache_dirname);
}

void
rcd_cache_expire_now (RCDCache *cache)
{
    char *cache_dirname;

    g_return_if_fail (cache != NULL);

    cache_dirname = rcd_cache_get_base_dir (cache);

    rcd_expire_all (cache_dirname, NULL, FALSE);

    g_free (cache_dirname);
}

static void
accumulate_size_cb (const char *file_name,
                    gsize       size_in_bytes,
                    double      age_in_secs,
                    gpointer    user_data)
{
    gsize *total_size = user_data;

    *total_size += size_in_bytes;
}

gsize
rcd_cache_size (RCDCache *cache)
{
    char *cache_dirname;
    gsize size = 0;

    g_return_val_if_fail (cache != NULL, 0);

    cache_dirname = rcd_cache_get_base_dir (cache);

    rcd_expire_foreach (cache_dirname, NULL, TRUE, accumulate_size_cb, &size);

    g_free (cache_dirname);

    return size;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

/* Define our global caches */

/* Replace any characters that might make this string unsafe to use
   as a filename. */

static char *
clean_str (const char *raw)
{
    char *cooked;
    char *p;

    cooked = g_strdup (raw);

    for (p = cooked; *p; ++p) {
        if (! (isalnum (*p) 
               || *p == '-' || *p == '.' || *p == '_' || *p == ':'))
            *p = '_';
    }

    return cooked;
}

static char *
normal_cache_base_dir_func (RCDCache *cache)
{
    return g_strconcat (rcd_prefs_get_cache_dir (), NULL);
}

static char *
package_cache_base_dir_func (RCDCache *cache)
{
    return g_strconcat (rcd_prefs_get_cache_dir (), "/packages", NULL);
}

static char *
normal_cache_filename_func (RCDCache *cache,
                            const char *source_id,
                            const char *file_tag)
{
    char *clean_source_id;
    char *clean_file_tag;
    char *filename;

    clean_source_id = clean_str (source_id);
    clean_file_tag = clean_str (file_tag);

    filename = g_strconcat (clean_source_id, "/", clean_file_tag, NULL);

    g_free (clean_source_id);
    g_free (clean_file_tag);

    return filename;
} /* normal_cache_filename_func */

static char *
package_cache_filename_func (RCDCache *cache,
                             const char *source_id,
                             const char *file_tag)
{
    return clean_str (file_tag);
} /* package_cache_filename_func */

RCDCache *
rcd_cache_get_normal_cache (void)
{
    static RCDCache *cache = NULL;

    if (cache == NULL) {
        cache = rcd_cache_new (normal_cache_base_dir_func,
                               normal_cache_filename_func,
                               NULL);
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
        cache = rcd_cache_new (package_cache_base_dir_func,
                               package_cache_filename_func,
                               rcd_transaction_check_package_integrity);
        
        rcd_shutdown_add_handler (shutdown_expire_package_cache,
                                  NULL);
    }

    return cache;
} /* rcd_cache_get_package_cache */

void
rcd_cache_expire_package_cache (void)
{
    if (rcd_prefs_get_cache_cleanup_enabled ()) {

        rcd_cache_expire (rcd_cache_get_package_cache (),
                          rcd_prefs_get_cache_max_age_in_days (),
                          rcd_prefs_get_cache_max_size_in_mb ());
    }
}



