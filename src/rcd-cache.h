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

#ifndef __RCD_CACHE_H__
#define __RCD_CACHE_H__

#include <glib.h>

typedef struct _RCDCache      RCDCache;
typedef struct _RCDCacheEntry RCDCacheEntry;

RCDCacheEntry *rcd_cache_entry_new (RCDCache *cache, const char *url);
RCDCacheEntry *rcd_cache_lookup    (RCDCache *cache, const char *url);

void rcd_cache_entry_open   (RCDCacheEntry *entry);
void rcd_cache_entry_append (RCDCacheEntry *entry,
                             const char    *data, 
                             gsize          size);
void rcd_cache_entry_close  (RCDCacheEntry *entry);
void rcd_cache_entry_cancel (RCDCacheEntry *entry);

const char *rcd_cache_entry_get_modification_time (RCDCacheEntry *entry);
const char *rcd_cache_entry_get_entity_tag        (RCDCacheEntry *entry);
void        rcd_cache_entry_set_modification_time (RCDCacheEntry *entry,
                                                   const char    *modtime);
void        rcd_cache_entry_set_entity_tag        (RCDCacheEntry *entry,
                                                   const char    *etag);

char *rcd_cache_entry_get_local_filename (RCDCacheEntry *entry);
char *rcd_cache_get_local_filename       (RCDCache *cache, const char *url);

RCDCache *rcd_cache_get_normal_cache  (void);
RCDCache *rcd_cache_get_package_cache (void);

#endif /* __RCD_CACHE_H__ */
