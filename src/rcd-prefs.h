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

gboolean rcd_prefs_get_auto_save (void);
void     rcd_prefs_set_auto_save (gboolean auto_save);
void     rcd_prefs_save          (void);

gboolean     rcd_prefs_get_remote_server_enabled (void);
gboolean     rcd_prefs_set_remote_server_enabled (gboolean);

int          rcd_prefs_get_remote_server_port (void);
gboolean     rcd_prefs_set_remote_server_port (int);

const gchar *rcd_prefs_get_bind_ipaddress     (void);
gboolean     rcd_prefs_set_bind_ipaddress     (const char *);

const gchar *rcd_prefs_get_cache_dir          (void);
gboolean     rcd_prefs_set_cache_dir          (const char *);

gboolean     rcd_prefs_get_cache_enabled      (void);
gboolean     rcd_prefs_set_cache_enabled      (gboolean);

const gchar *rcd_prefs_get_host               (void);
gboolean     rcd_prefs_set_host               (const char *);

gboolean     rcd_prefs_get_premium            (void);
gboolean     rcd_prefs_set_premium            (gboolean);

const gchar *rcd_prefs_get_proxy              (void);

const gchar *rcd_prefs_get_proxy_url          (void);
gboolean     rcd_prefs_set_proxy_url          (const char *);

const gchar *rcd_prefs_get_proxy_username     (void);
gboolean     rcd_prefs_set_proxy_username     (const char *);

const gchar *rcd_prefs_get_proxy_password     (void);
gboolean     rcd_prefs_set_proxy_password     (const char *);

const gchar *rcd_prefs_get_org_id             (void);

gboolean     rcd_prefs_get_http10_enabled     (void);
gboolean     rcd_prefs_set_http10_enabled     (gboolean);

gboolean     rcd_prefs_get_require_verified_certificates (void);
gboolean     rcd_prefs_set_require_verified_certificates (gboolean);

guint32      rcd_prefs_get_heartbeat_interval (void);
gboolean     rcd_prefs_set_heartbeat_interval (guint32);

int          rcd_prefs_get_max_downloads (void);
gboolean     rcd_prefs_set_max_downloads (int);

gboolean     rcd_prefs_get_require_signed_packages (void);
gboolean     rcd_prefs_set_require_signed_packages (gboolean);

gint         rcd_prefs_get_debug_level        (void);
gboolean     rcd_prefs_set_debug_level        (gint);

gint         rcd_prefs_get_syslog_level       (void);
gboolean     rcd_prefs_set_syslog_level       (gint);

gboolean     rcd_prefs_get_cache_cleanup_enabled (void);
gboolean     rcd_prefs_set_cache_cleanup_enabled (gboolean);

gint         rcd_prefs_get_cache_max_age_in_days (void);
gboolean     rcd_prefs_set_cache_max_age_in_days (gint);

gint         rcd_prefs_get_cache_max_size_in_mb (void);
gboolean     rcd_prefs_set_cache_max_size_in_mb (gint);

gboolean     rcd_prefs_get_rollback (void);
gboolean     rcd_prefs_set_rollback (gboolean);

/* These aren't really prefs, but there here for lack of a better place */
const gchar *rcd_prefs_get_mid                (void);
const gchar *rcd_prefs_get_secret             (void);

/* Generic get/set functions for modules */
const char *rcd_prefs_get_string  (const char *path);
void        rcd_prefs_set_string  (const char *path, const char *str);

int         rcd_prefs_get_int     (const char *path);
void        rcd_prefs_set_int     (const char *path, int val);

gboolean    rcd_prefs_get_boolean (const char *path);
void        rcd_prefs_set_boolean (const char *path, gboolean val);

#endif /* __RCD_PREFS_H__ */
