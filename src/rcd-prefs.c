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
#include <libsoup/soup-misc.h>
#include <libsoup/soup-uri.h>

#include "gnome-config.h"
#include "rcd-heartbeat.h"

#define DEFAULT_CONFIG_FILE SYSCONFDIR "/rcd.conf"
#define SYNC_CONFIG (gnome_config_sync_file ((char *) get_config_path (NULL)))

const char *
get_config_path (const char *path)
{
    /*
     * Ugh.  I dislike externing this.  It's one of the options in
     * rcd.c.
     */
    extern char *config_file;
    static char *config_path = NULL;

    g_free (config_path);

    config_path = g_strdup_printf (
        "=%s=%s", 
        config_file ? config_file : DEFAULT_CONFIG_FILE,
        path ? path : "");

    return config_path;
} /* get_config_file */

const char *
rcd_prefs_get_string (const char *path)
{
    static char *str = NULL;

    g_free (str);

    str = gnome_config_get_string (get_config_path (path));

    return str;
} /* rcd_prefs_get_string */

void
rcd_prefs_set_string (const char *path, const char *str)
{
    gnome_config_set_string (get_config_path (path), str);
    SYNC_CONFIG;
}

int
rcd_prefs_get_int (const char *path)
{
    return gnome_config_get_int (get_config_path (path));
}

void
rcd_prefs_set_int (const char *path, int val)
{
    gnome_config_set_int (get_config_path (path), val);
    SYNC_CONFIG;
}

gboolean
rcd_prefs_get_boolean (const char *path)
{
    return gnome_config_get_bool (get_config_path (path));
}

void
rcd_prefs_set_boolean (const char *path, gboolean val)
{
    gnome_config_set_bool (get_config_path (path), val);
    SYNC_CONFIG;
}

gboolean
rcd_prefs_get_remote_server_enabled (void)
{
    return gnome_config_get_bool (
        get_config_path ("/Server/remote-enabled=TRUE"));
} /* rcd_prefs_get_remote_server_enabled */

int
rcd_prefs_get_remote_server_port (void)
{
    return gnome_config_get_int (get_config_path ("/Server/port=505"));
} /* rcd_prefs_get_remote_server_port */

const char *
rcd_prefs_get_cache_dir (void)
{
    static char *cache_dir = NULL;

    g_free (cache_dir);

    cache_dir = gnome_config_get_string (
        get_config_path ("/Cache/directory=/var/cache/redcarpet"));

    return cache_dir;
}

void
rcd_prefs_set_cache_dir (const char *cache_dir)
{
    gnome_config_set_string (get_config_path ("/Cache/directory"), cache_dir);
    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Cache dir set: %s", cache_dir);

    SYNC_CONFIG;
}

gboolean
rcd_prefs_get_cache_enabled (void)
{
    return gnome_config_get_bool (get_config_path ("/Cache/enabled=TRUE"));
}

void
rcd_prefs_set_cache_enabled (gboolean enabled)
{
    gnome_config_set_bool (get_config_path ("/Cache/enabled"), enabled);
    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Cache dir enabled: %s",
              enabled ? "TRUE" : "FALSE");

    SYNC_CONFIG;
}

const char *
rcd_prefs_get_host (void)
{
    static char *host = NULL;

    g_free (host);

    host = gnome_config_get_string (
        get_config_path ("/Network/host=http://red-carpet.ximian.com"));

    return host;
} /* rcd_prefs_get_host */

void
rcd_prefs_set_host (const char *host)
{
    if (!host) {
        rc_debug (RC_DEBUG_LEVEL_WARNING, "Can't set empty host!");
        return;
    }

    gnome_config_set_string (get_config_path ("/Network/host"), host);
    SYNC_CONFIG;
} /* rcd_prefs_set_host */

gboolean
rcd_prefs_get_premium (void)
{
    return gnome_config_get_bool (
        get_config_path ("/Network/enable-premium=FALSE"));
} /* rcd_prefs_get_premium */

void
rcd_prefs_set_premium (gboolean enabled)
{
    gnome_config_set_bool (
        get_config_path ("/Network/enable-premium"), enabled);

    SYNC_CONFIG;
} /* rcd_prefs_set_premium */

const char *
rcd_prefs_get_org_id (void)
{
    static char *org_id = NULL;

    g_free (org_id);
    org_id = NULL;

    org_id = gnome_config_get_string (get_config_path ("/Network/org-id"));

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

    proxy = gnome_config_get_string (get_config_path ("/Network/proxy"));

    if (!proxy)
        return NULL;

    proxy_user = gnome_config_get_string (
        get_config_path ("/Network/proxy-user"));
    proxy_passwd = gnome_config_get_string (
        get_config_path ("/Network/proxy-password"));

    proxy_uri = soup_uri_new (proxy);

    if (!proxy_uri) {
        rc_debug (RC_DEBUG_LEVEL_WARNING, "Invalid proxy URL: %s", proxy);
        return proxy;
    }

    proxy_uri->user = proxy_user;
    proxy_uri->passwd = proxy_passwd;
    g_free (proxy);

    proxy_url = soup_uri_to_string (proxy_uri, TRUE);
    soup_uri_free (proxy_uri);

    return proxy_url;
} /* rcd_prefs_get_proxy */

const char *
rcd_prefs_get_proxy_url (void)
{
    static char *proxy = NULL;

    g_free (proxy);
    proxy = NULL;

    proxy = gnome_config_get_string (get_config_path ("/Network/proxy"));

    if (!proxy)
        return NULL;

    return proxy;
} /* rcd_prefs_get_proxy_url */

void
rcd_prefs_set_proxy_url (const char *proxy_url)
{
    if (proxy_url) {
        gnome_config_set_string (
            get_config_path ("/Network/proxy"), proxy_url);
        rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Proxy URL set: %s", proxy_url);
    }
    else {
        gnome_config_clean_key (get_config_path ("/Network/proxy"));
        rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Proxy URL unset");
    }

    SYNC_CONFIG;
}

const char *
rcd_prefs_get_proxy_username (void)
{
    static char *proxy_username = NULL;

    g_free (proxy_username);
    proxy_username = NULL;

    proxy_username = gnome_config_get_string (
        get_config_path ("/Network/proxy-user"));

    if (!proxy_username)
        return NULL;

    return proxy_username;
} /* rcd_prefs_get_proxy_username */

void
rcd_prefs_set_proxy_username (const char *proxy_username)
{
    if (proxy_username) {
        gnome_config_set_string (get_config_path ("/Network/proxy-user"),
                                 proxy_username);

        rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Proxy username set: %s",
                  proxy_username);
    }
    else {
        gnome_config_clean_key (get_config_path ("/Network/proxy-user"));
        rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Proxy username unset");
    }

    SYNC_CONFIG;
}

const char *
rcd_prefs_get_proxy_password (void)
{
    static char *proxy_password = NULL;

    g_free (proxy_password);
    proxy_password = NULL;

    proxy_password = gnome_config_get_string (
        get_config_path ("/Network/proxy-password"));

    if (!proxy_password)
        return NULL;

    return proxy_password;
} /* rcd_prefs_get_proxy_password */

void
rcd_prefs_set_proxy_password (const char *proxy_password)
{
    if (proxy_password) {
        gnome_config_set_string (
            get_config_path ("/Network/proxy-password"), proxy_password);
        rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Proxy password set");
    }
    else {
        gnome_config_clean_key (get_config_path ("/Network/proxy-password"));
        rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Proxy password unset");
    }

    SYNC_CONFIG;
}

gboolean
rcd_prefs_get_http10_enabled (void)
{
    return gnome_config_get_bool (get_config_path ("/Network/http10=FALSE"));
}

void
rcd_prefs_set_http10_enabled (gboolean enabled)
{
    gnome_config_set_bool (get_config_path ("/Network/http10"), enabled);
    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "HTTP 1.0 enabled: %s",
              enabled ? "TRUE" : "FALSE");

    SYNC_CONFIG;
}

gboolean
rcd_prefs_get_require_verified_certificates (void)
{
    return gnome_config_get_bool (get_config_path ("/Network/require-verified-certificates=TRUE"));
}

void
rcd_prefs_set_require_verified_certificates (gboolean enabled)
{
    gnome_config_set_bool (get_config_path ("/Network/require-verified-certificates"), enabled);

    soup_set_ssl_ca_dir (enabled ? SHAREDIR "/ca" : NULL);

    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "SSL Certificate verification %s",
              enabled ? "enabled" : "disabled");

    SYNC_CONFIG;
}

guint32
rcd_prefs_get_heartbeat_interval (void)
{
    /* 21600 seconds == 6 hours */
    return (guint32) gnome_config_get_int (
        get_config_path ("/System/heartbeat=21600"));
} /* rcd_prefs_get_heartbeat_interval */

#define HEARTBEAT_MINIMUM 1800
void
rcd_prefs_set_heartbeat_interval (guint32 interval)
{
    guint32 old_interval;

    if (interval != 0 && interval < HEARTBEAT_MINIMUM) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Heartbeat frequencies less than %d are not allowed.",
                  HEARTBEAT_MINIMUM);
        return;
    }

    old_interval = rcd_prefs_get_heartbeat_interval ();

    if (old_interval && !interval)
        rcd_heartbeat_stop ();

    gnome_config_set_int (
        get_config_path ("/System/heartbeat"), (int) interval);
    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Setting heartbeat to %u seconds",
              interval);

    SYNC_CONFIG;

    if (!old_interval && interval)
        rcd_heartbeat_start ();
}

int
rcd_prefs_get_max_downloads (void)
{
    return gnome_config_get_int (
        get_config_path ("/Network/max-downloads=5"));
} /* rcd_prefs_get_max_downloads */

void
rcd_prefs_set_max_downloads (int max_downloads)
{
    if (max_downloads < 0)
        max_downloads = 0;

    gnome_config_set_int (
        get_config_path ("/Network/max-downloads"), max_downloads);

    SYNC_CONFIG;
} /* rcd_prefs_set_max_downloads */

gboolean
rcd_prefs_get_require_signed_packages (void)
{
    return gnome_config_get_bool (
        get_config_path ("/System/require-signatures=TRUE"));
} /* rcd_prefs_get_require_signed_packages */

void
rcd_prefs_set_require_signed_packages (gboolean enabled)
{
    gnome_config_set_bool (
        get_config_path ("/System/require-signatures"), enabled);
    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Signatures required for install: %s",
              enabled ? "TRUE" : "FALSE");

    SYNC_CONFIG;
} /* rcd_prefs_set_require_signed_packages */

gint
rcd_prefs_get_debug_level (void)
{
    /* Command-line debug level option */
    extern int debug_level;

    if (debug_level > -1)
        return debug_level;

    return gnome_config_get_int (
        get_config_path ("/System/debug-level=4"));
} /* rcd_prefs_get_debug_level */

void
rcd_prefs_set_debug_level (gint level)
{
    /* Command-line debug level option */
    extern int debug_level;

    /* Don't obey the command-line option anymore */
    debug_level = -1;

    gnome_config_set_int (
        get_config_path ("/System/debug-level"), level);
    SYNC_CONFIG;
} /* rcd_prefs_set_debug_level */

gint
rcd_prefs_get_syslog_level (void)
{
    /* Command-line debug level option */
    extern int syslog_level;

    if (syslog_level > -1)
        return syslog_level;

    return gnome_config_get_int (
        get_config_path ("/System/syslog-level=4"));
} /* rcd_prefs_get_syslog_level */

void
rcd_prefs_set_syslog_level (gint level)
{
    /* Command-line debug level option */
    extern int syslog_level;

    /* Don't obey the command-line option anymore */
    syslog_level = -1;

    gnome_config_set_int (
        get_config_path ("/System/syslog-level"), level);

    SYNC_CONFIG;
} /* rcd_prefs_set_syslog_level */

gboolean
rcd_prefs_get_cache_cleanup_enabled (void)
{
    return gnome_config_get_bool (
        get_config_path ("/System/cache-cleanup=TRUE"));
}

void
rcd_prefs_set_cache_cleanup_enabled (gboolean enabled)
{
    gnome_config_set_bool (
        get_config_path ("/System/cache-cleanup"), enabled);

    SYNC_CONFIG;
}

gint
rcd_prefs_get_cache_max_age_in_days (void)
{
    return gnome_config_get_int (
        get_config_path ("/System/cache-age-in-days=30"));
}

void
rcd_prefs_set_cache_max_age_in_days (gint days)
{
    if (days < 0)
        days = 0;

    gnome_config_set_int (
        get_config_path ("/System/cache-age-in-days"), days);

    SYNC_CONFIG;
}

gint
rcd_prefs_get_cache_max_size_in_mb (void)
{
    return gnome_config_get_int (
        get_config_path ("/System/cache-size-in-mb=300"));
}

void
rcd_prefs_set_cache_max_size_in_mb (gint size)
{
    if (size < 0)
        size = 0;

    gnome_config_set_int (
        get_config_path ("/System/cache-size-in-mb"), size);

    SYNC_CONFIG;
}

gboolean
rcd_prefs_get_repackage (void)
{
    return gnome_config_get_bool (get_config_path ("/System/repackage=FALSE"));
}

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
