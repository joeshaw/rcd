/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-prefs.h
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

#ifndef __RCD_PREFS_H__
#define __RCD_PREFS_H__

#include <glib.h>

gboolean     rcd_prefs_get_remote_server_enabled (void);

int          rcd_prefs_get_remote_server_port (void);

const gchar *rcd_prefs_get_cache_dir          (void);
void         rcd_prefs_set_cache_dir          (const char *);

gboolean     rcd_prefs_get_cache_enabled      (void);
void         rcd_prefs_set_cache_enabled      (gboolean);

const gchar *rcd_prefs_get_host               (void);
const gchar *rcd_prefs_get_proxy              (void);

gboolean     rcd_prefs_get_http10_enabled     (void);
void         rcd_prefs_set_http10_enabled     (gboolean);

gboolean     rcd_prefs_get_premium            (void);

guint32      rcd_prefs_get_heartbeat_interval (void);
void         rcd_prefs_set_heartbeat_interval (guint32);

gboolean     rcd_prefs_get_require_verified_packages (void);

#endif /* __RCD_PREFS_H__ */

