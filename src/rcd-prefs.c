/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-prefs.c
 *
 * Copyright (C) 2002 Ximian, Inc.
 *
 * Developed by Jon Trowbridge <trow@ximian.com>
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
#include "rcd-prefs.h"

#include <stdlib.h>

#include <rc-debug.h>

const char *
rcd_prefs_get_cache_dir (void)
{
    /* return "/var/cache/redcarpet"; */ /* FIXME */
    return "/tmp/rcd-cache";
}

void
rcd_prefs_set_cache_dir (const char *cache_dir)
{
    /* FIXME */
    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Cache dir set: %s", cache_dir);
}

gboolean
rcd_prefs_get_cache_enabled (void)
{
    return TRUE;
}

void
rcd_prefs_set_cache_enabled (gboolean enabled)
{
    /* FIXME */
    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Cache dir enabled: %s",
              enabled ? "TRUE" : "FALSE");
}

const char *
rcd_prefs_get_host (void)
{
    char *host;

    if ((host = getenv ("RC_MAGIC")))
        return host;
    else
        return "http://red-carpet.ximian.com";
}

gboolean
rcd_prefs_get_http10_enabled (void)
{
    return FALSE;
}

void
rcd_prefs_set_http10_enabled (gboolean enabled)
{
    /* FIXME */
    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "HTTP 1.0 enabled: %s",
              enabled ? "TRUE" : "FALSE");
}

gboolean
rcd_prefs_get_priority (void)
{
    return FALSE;
}

guint32
rcd_prefs_get_heartbeat_interval (void)
{
    return 3000;
} /* rcd_prefs_get_heartbeat_interval */

void
rcd_prefs_set_heartbeat_interval (guint32 interval)
{
    /* FIXME */
    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "heartbeat: %d", interval);
}

gboolean
rcd_prefs_get_require_verified_packages (void)
{
    return FALSE;
} /* rcd_prefs_get_require_verified_packages */
