/* This is -*- C -*- */
/* vim: set sw=2: */
/* $Id$ */

/*
 * rcd-expire.c
 *
 * Copyright (C) 2002 The Free Software Foundation, Inc.
 *
 * Developed by Jon Trowbridge <trow@gnu.org>
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
#include "rcd-expire.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libredcarpet.h>

typedef void (*RCDExpireFn) (const char *full_path,
			     int         size_in_bytes,
			     double      age_in_secs,
			     gpointer    user_data);
static void
rcd_expire_foreach (const char *base_path,
		    const char *glob,
		    gboolean    recursive,
		    RCDExpireFn fn,
		    gpointer    user_data)
{
  GDir *dir;
  GPatternSpec *pattern = NULL;
  const char *file_name;
  time_t now;

  g_return_if_fail (base_path && *base_path);
  g_return_if_fail (fn);

  dir = g_dir_open (base_path, 0, NULL);

  if (dir == NULL) {
    rc_debug (RC_DEBUG_LEVEL_WARNING,
	      "Couldn't open directory '%s' for expiration",
	      base_path);
    return;
  }

  if (glob)
    pattern = g_pattern_spec_new (glob);

  time (&now);

  while ((file_name = g_dir_read_name (dir))) {

    if (strcmp (file_name, ".")	&& strcmp (file_name, "..")) {
      char *path = g_strconcat (base_path, "/", file_name, NULL);

      if (recursive && g_file_test (path, G_FILE_TEST_IS_DIR)) {

	/* If appropriate, recursively descend into subdirectories. */

	rcd_expire_foreach (path, glob, recursive, fn, user_data);

      } else if (pattern == NULL || g_pattern_match_string (pattern, file_name)) {
	struct stat buf;

	/* Otherwise call fn on file names that match the pattern. */

	if (stat (path, &buf) == 0) {
	  
	  fn (path, 
	      buf.st_size, 
	      difftime (now, buf.st_mtime),
	      user_data);
	}
      }

      g_free (path);
    }
  }

  g_dir_close (dir);

  if (pattern)
    g_pattern_spec_free (pattern);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static void
expire_by_age_cb (const char *file_name,
		  int         size_in_bytes,
		  double      age_in_secs,
		  gpointer user_data)
{
  double max_age_in_days = *(double *) user_data;
  double age_in_days = age_in_secs / (24 * 60 * 60);

  if (age_in_days >= max_age_in_days) {
    unlink (file_name);
  }
}

void
rcd_expire_by_age (const char *base_path,
		   const char *glob,
		   gboolean    recursive,
		   double      max_age_in_days)
{
  g_return_if_fail (base_path);
  g_return_if_fail (max_age_in_days > 0);

  rcd_expire_foreach (base_path, glob, recursive, expire_by_age_cb, &max_age_in_days);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

typedef struct {
  char *file_name;
  double size_in_mb;
  double age_in_days;
} CacheItem;

/* Sorts oldest to youngest */
static int
cache_item_cmp (CacheItem *a,
		CacheItem *b)
{
  return (a->age_in_days < b->age_in_days) - (a->age_in_days > b->age_in_days);
}

static void
build_list_cb (const char *file_name,
	       int         size_in_bytes,
	       double      age_in_secs,
	       gpointer    user_data)
{
  CacheItem *ci = g_new0 (CacheItem, 1);
  GList **list = user_data;

  ci->file_name = g_strdup (file_name);
  ci->size_in_mb = size_in_bytes / (double)(1024 * 1024);
  ci->age_in_days = age_in_secs / (24 * 60 * 60);

  *list = g_list_prepend (*list, ci);
}

void
rcd_expire_by_size (const char *base_path,
		    const char *glob,
		    gboolean    recursive,
		    double      max_size_in_mb,
		    double      min_age_in_days)
{
  GList *list = NULL, *iter;
  double total_size = 0;

  g_return_if_fail (base_path != NULL);
  g_return_if_fail (max_size_in_mb > 0);
  
  /* Build a list of the candidates for expiration. */
  rcd_expire_foreach (base_path, glob, recursive, build_list_cb, &list);

  /* Sort our list of files from oldest to youngest. */
  list = g_list_sort (list, (GCompareFunc) cache_item_cmp);
  
  /* Tally up the total size of our files. */
  for (iter = list; iter != NULL; iter = iter->next) {
    CacheItem *ci = iter->data;
    total_size += ci->size_in_mb;
  }

  /* Delete files until our total size drops below the prescribed maximum. */
  for (iter = list; iter != NULL && total_size > max_size_in_mb; iter = iter->next) {
    CacheItem *ci = iter->data;

    /* We refuse to expire a file that is less than min_age_in_days days old. */
    if (ci->age_in_days < min_age_in_days)
      break;

    unlink (ci->file_name);
  }

  /* Clean up our list of cache items. */
  for (iter = list; iter != NULL; iter = iter->next) {
    CacheItem *ci = iter->data;
    g_free (ci->file_name);
    g_free (ci);
  }
  g_list_free (list);
}




