/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-prefs.c
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
#include "rcd-prefs.h"

#include <stdlib.h>

#include <rc-debug.h>

#include "gnome-config.h"

#define OVERRIDE_PATH "=" SYSCONFDIR "/rc.overrides="
#define CONFIG_PATH "=" SYSCONFDIR "/rcd.config="
#define SYNC_CONFIG (gnome_config_sync_file (CONFIG_PATH))

const char *
rcd_prefs_get_cache_dir (void)
{
    static char *cache_dir = NULL;

    g_free (cache_dir);

    /* FIXME: /var/cache/redcarpet as the default instead */
    cache_dir = gnome_config_get_string (
        CONFIG_PATH "/Cache/directory=/tmp/rcd-cache");

    return cache_dir;
}

void
rcd_prefs_set_cache_dir (const char *cache_dir)
{
    gnome_config_set_string (CONFIG_PATH "/Cache/directory", cache_dir);
    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Cache dir set: %s", cache_dir);

    SYNC_CONFIG;
}

gboolean
rcd_prefs_get_cache_enabled (void)
{
    return gnome_config_get_bool (CONFIG_PATH "/Cache/enabled=TRUE");
}

void
rcd_prefs_set_cache_enabled (gboolean enabled)
{
    gnome_config_set_bool (CONFIG_PATH "/Cache/enabled", enabled);
    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Cache dir enabled: %s",
              enabled ? "TRUE" : "FALSE");

    SYNC_CONFIG;
}

const char *
rcd_prefs_get_host (void)
{
    static char *host = NULL;

    g_free (host);
    host = NULL;

    if (getenv ("RCX_MAGIC"))
        return getenv ("RCX_MAGIC");

    if (getenv ("RC_MAGIC"))
        return getenv ("RC_MAGIC");

    host = gnome_config_get_string (
        CONFIG_PATH "/Network/host=http://red-carpet.ximian.com");

    return host;
} /* rcd_prefs_get_host */

gboolean
rcd_prefs_get_premium (void)
{
    if (getenv ("RCX_MAGIC"))
        return TRUE;
    else if (getenv ("RC_MAGIC"))
        return FALSE;
    else {
        return gnome_config_get_bool (
            CONFIG_PATH "/Network/enable-premium=FALSE");
    }
} /* rcd_prefs_get_premium */

gboolean
rcd_prefs_get_http10_enabled (void)
{
    return gnome_config_get_bool (CONFIG_PATH "/Network/http10=FALSE");
}

void
rcd_prefs_set_http10_enabled (gboolean enabled)
{
    gnome_config_set_bool (CONFIG_PATH "/Network/http10", enabled);
    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "HTTP 1.0 enabled: %s",
              enabled ? "TRUE" : "FALSE");

    SYNC_CONFIG;
}

guint32
rcd_prefs_get_heartbeat_interval (void)
{
    return (guint32) gnome_config_get_int (
        CONFIG_PATH "/System/heartbeat=3000");
} /* rcd_prefs_get_heartbeat_interval */

void
rcd_prefs_set_heartbeat_interval (guint32 interval)
{
    gnome_config_set_int (CONFIG_PATH "/System/heartbeat", (int) interval);
    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "heartbeat: %u", interval);

    SYNC_CONFIG;
}

gboolean
rcd_prefs_get_require_verified_packages (void)
{
    return gnome_config_get_bool (
        CONFIG_PATH "/System/require-verified=FALSE");
} /* rcd_prefs_get_require_verified_packages */
