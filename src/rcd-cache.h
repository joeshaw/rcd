/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * rcd-cache.h: Cache implementation for RCDTransfers
 *
 * Copyright (C) 2000-2002 Ximian, Inc.
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

#ifndef _RCD_CACHE_H
#define _RCD_CACHE_H

#include <glib.h>
#include <time.h>

typedef struct _RCDCache RCDCache;

void rcd_cache_set_user_data(RCDCache *cache, gpointer user_data);
gpointer rcd_cache_get_user_data(RCDCache *cache);
char *rcd_cache_get_cache_directory(RCDCache *cache);
char *rcd_cache_get_cache_filename(RCDCache *cache, const char *filename);
const char *rcd_cache_get_modification_time(RCDCache *cache, const char *filename);
void rcd_cache_open(RCDCache *cache, const char *filename, gboolean append);
void rcd_cache_append(RCDCache *cache, const char *filename, const char *data, guint32 size);
void rcd_cache_close(RCDCache *cache, const char *filename);
void rcd_cache_invalidate(RCDCache *cache, const char *filename);
void rcd_cache_invalidate_all(RCDCache *cache);
void rcd_cache_invalidate_all_older(RCDCache *cache, time_t seconds);
gboolean rcd_cache_is_active(RCDCache *cache, const char *filename);

RCDCache *rcd_cache_get_package_cache (void);
RCDCache *rcd_cache_get_icon_cache    (void);
RCDCache *rcd_cache_get_normal_cache  (void);

#endif /* _RCD_CACHE_H */
