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

#include <libredcarpet.h>
#include <libsoup/soup-uri.h>

#include "gnome-config.h"

#define OVERRIDE_PATH "=" SYSCONFDIR "/rc.overrides="
#define CONFIG_PATH "=" SYSCONFDIR "/rcd.config="
#define SYNC_CONFIG (gnome_config_sync_file (CONFIG_PATH))

gboolean
rcd_prefs_get_remote_server_enabled (void)
{
    return gnome_config_get_bool (CONFIG_PATH "/Server/enabled=TRUE");
} /* rcd_prefs_get_remote_server_enabled */

int
rcd_prefs_get_remote_server_port (void)
{
    return gnome_config_get_int (CONFIG_PATH "/Server/port=505");
} /* rcd_prefs_get_remote_server_port */

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
rcd_prefs_get_registered (void)
{
    return gnome_config_get_bool (CONFIG_PATH "/Network/registered=FALSE");
} /* rcd_prefs_get_registered */

void
rcd_prefs_set_registered (gboolean registered)
{
    gnome_config_set_bool (CONFIG_PATH "/Network/registered", registered);

    SYNC_CONFIG;
} /* rcd_prefs_set_registered */

const char *
rcd_prefs_get_org_id (void)
{
    static char *org_id = NULL;

    g_free (org_id);
    org_id = NULL;

    org_id = gnome_config_get_string (CONFIG_PATH "/Network/org_id");

    return org_id;
} /* rcd_prefs_get_org_id */

const char *
rcd_prefs_get_proxy (void)
{
    static char *proxy_url = NULL;
    char *proxy;
    SoupUri *proxy_uri;
    char *proxy_user;
    char *proxy_passwd;

    g_free (proxy_url);
    proxy_url = NULL;

    proxy = gnome_config_get_string (CONFIG_PATH "/Network/proxy");
    
    if (!proxy)
        return NULL;

    proxy_user = gnome_config_get_string (CONFIG_PATH "/Network/proxy-user");
    proxy_passwd = gnome_config_get_string (
        CONFIG_PATH "/Network/proxy-password");

    proxy_uri = soup_uri_new (proxy);
    proxy_uri->user = proxy_user;
    proxy_uri->passwd = proxy_passwd;
    g_free (proxy);

    proxy_url = soup_uri_to_string (proxy_uri, TRUE);
    soup_uri_free (proxy_uri);

    return proxy_url;
} /* rcd_prefs_get_proxy */

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
    /* 21600 seconds == 6 hours */
    return (guint32) gnome_config_get_int (
        CONFIG_PATH "/System/heartbeat=21600");
} /* rcd_prefs_get_heartbeat_interval */

#define HEARTBEAT_MINIMUM 1800
void
rcd_prefs_set_heartbeat_interval (guint32 interval)
{
    if (interval < HEARTBEAT_MINIMUM) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Heartbeat frequencies less than %d are not allowed.",
                  HEARTBEAT_MINIMUM);
        return;
    }

    gnome_config_set_int (CONFIG_PATH "/System/heartbeat", (int) interval);
    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "heartbeat: %u", interval);

    SYNC_CONFIG;
}

int
rcd_prefs_get_max_downloads (void)
{
    return gnome_config_get_int (
        CONFIG_PATH "/Network/max-downloads=5");
} /* rcd_prefs_get_max_downloads */

void
rcd_prefs_set_max_downloads (int max_downloads)
{
    if (max_downloads < 0)
        max_downloads = 0;

    gnome_config_set_int (
        CONFIG_PATH "/Network/max-downloads", max_downloads);

    SYNC_CONFIG;
} /* rcd_prefs_set_max_downloads */

gboolean
rcd_prefs_get_require_verified_packages (void)
{
    return gnome_config_get_bool (
        CONFIG_PATH "/System/require-verified=FALSE");
} /* rcd_prefs_get_require_verified_packages */

gint
rcd_prefs_get_debug_level (void)
{
    return gnome_config_get_int (
        CONFIG_PATH "/System/debug-level=4");
} /* rcd_prefs_get_debug_level */

void
rcd_prefs_set_debug_level (gint level)
{
    gnome_config_set_int (
        CONFIG_PATH "/System/debug-level", level);
    SYNC_CONFIG;
} /* rcd_prefs_set_debug_level */

gint
rcd_prefs_get_syslog_level (void)
{
    return gnome_config_get_int (
        CONFIG_PATH "/System/syslog-level=4");
} /* rcd_prefs_get_syslog_level */

void
rcd_prefs_set_syslog_level (gint level)
{
    gnome_config_set_int (
        CONFIG_PATH "/System/syslog-level", level);
    SYNC_CONFIG;
} /* rcd_prefs_set_syslog_level */

const char *
rcd_prefs_get_mid (void)
{
    static char *mid = NULL;
    RCBuffer *buf;

    g_free (mid);
    mid = NULL;

    buf = rc_buffer_map_file (SYSCONFDIR "/mcookie");
    if (!buf)
        return NULL;

    mid = g_strndup (buf->data, 36);
    mid[36] = '\0';

    rc_buffer_unmap_file (buf);

    return mid;
} /* rcd_prefs_get_mid */

const char *
rcd_prefs_get_secret (void)
{
    static char *secret = NULL;
    RCBuffer *buf;

    g_free (secret);
    secret = NULL;

    buf = rc_buffer_map_file (SYSCONFDIR "/partnernet");
    if (!buf)
        return NULL;

    secret = g_strndup (buf->data, 36);
    secret[36] = '\0';

    rc_buffer_unmap_file (buf);

    return secret;
} /* rcd_prefs_get_secret */
