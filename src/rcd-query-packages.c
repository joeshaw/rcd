/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-query-packages.c
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
#include "rcd-query-packages.h"

static gboolean
name_match (RCDQueryPart *part,
            gpointer      data)
{
    RCPackage *pkg = data;
    return rcd_query_match_string (part, pkg->spec.name);
}

static gboolean
summary_match (RCDQueryPart *part,
            gpointer      data)
{
    RCPackage *pkg = data;
    return rcd_query_match_string (part, pkg->summary);
}

static gboolean
description_match (RCDQueryPart *part,
                   gpointer      data)
{
    RCPackage *pkg = data;
    return rcd_query_match_string (part, pkg->description);
}

#define SYSTEM_HACK (guint)(~0)

static void
channel_init (RCDQueryPart *part)
{
    int code;
    char *endptr;

    if (! g_strcasecmp (part->query_str, "system")) {
        part->data = GUINT_TO_POINTER (SYSTEM_HACK);
        return;
    }

    code = strtol (part->query_str, &endptr, 10);
    if (endptr != NULL && *endptr == '\0') {
        part->data = GUINT_TO_POINTER (code);
    } else
        part->data = NULL;
}

static gboolean
channel_match (RCDQueryPart *part,
               gpointer      data) 
{
    RCPackage *pkg = data;

    /* Match against our cached id */
    if (part->data != NULL) {
        guint32 id;        
        if (pkg->channel == NULL)
            id = SYSTEM_HACK;
        else
            id = rc_channel_get_id (pkg->channel);

        return rcd_query_type_int_compare (part->type, id, GPOINTER_TO_UINT (part->data));
    }

    if (pkg->channel == NULL)
        return FALSE;
    
    /* Fallback: match against name */
    return rcd_query_match_string (part, rc_channel_get_name (pkg->channel));
}

static gboolean
installed_match (RCDQueryPart *part,
                 gpointer      data)
{
    RCPackage *pkg = data;
    rcd_query_match_bool (part, pkg->channel == NULL);
}

static gboolean
needs_upgrade_match (RCDQueryPart *part,
                   gpointer      data)
{
    RCPackage *pkg = data;
    rcd_query_match_bool (part,
                          pkg->channel == NULL /* must be installed */
                          && rc_world_get_best_upgrade (rc_get_world (), pkg) != NULL);
}

static gboolean
importance_validate (RCDQueryPart *part)
{
    RCPackageImportance imp = rc_string_to_package_importance (part->query_str);

    if (imp == RC_IMPORTANCE_INVALID)
        return FALSE;

    part->data = GINT_TO_POINTER (imp);
    return TRUE;
}

static gboolean
importance_match (RCDQueryPart *part, 
                  gpointer      data)
{
    RCPackage *pkg = data;
    RCPackageImportance imp;

    /* Installed packages automatically fail. */
    if (pkg->channel == NULL
        || pkg->history == NULL
        || pkg->history->data == NULL)
        return FALSE;

    imp = ((RCPackageUpdate *) pkg->history->data)->importance;
    
    return rcd_query_type_int_compare (part->type,
                                       GPOINTER_TO_INT (part->data), (gint) imp);
}


/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static RCDQueryEngine query_packages_engine[] = {
    { "name",
      NULL, NULL, NULL,
      name_match },
    
    { "summary",
      NULL, NULL, NULL,
      summary_match },

    { "description",
      NULL, NULL, NULL, 
      description_match },

    { "channel",
      NULL, channel_init, NULL,
      channel_match },

    { "installed",
      rcd_query_validate_bool, NULL, NULL,
      installed_match },

    { "needs_upgrade",
      rcd_query_validate_bool, NULL, NULL,
      needs_upgrade_match },

    { "importance",
      importance_validate, NULL, NULL,
      importance_match },

    { NULL, NULL, NULL, NULL, NULL }
};

struct QueryInfo {
    RCDQueryPart *query_parts;
    RCPackageFn   matching_package_cb;
    gpointer      user_data;
    gint          count;
};

void
match_package_fn (RCPackage *pkg, gpointer user_data)
{
    struct QueryInfo *info = user_data;

    if (rcd_query_match (info->query_parts, 
                         query_packages_engine, 
                         pkg)) {
        
        if (info->matching_package_cb)
            info->matching_package_cb (pkg, info->user_data);

        ++info->count;
    }
}
      
gint
rcd_query_packages (RCWorld      *world,
                     RCDQueryPart *query_parts,
                     RCPackageFn   matching_package_cb,
                     gpointer      user_data)
{
    struct QueryInfo info;

    g_return_val_if_fail (world != NULL, -1);

    if (! rcd_query_begin (query_parts, query_packages_engine))
        return -1;

    info.query_parts = query_parts;
    info.matching_package_cb = matching_package_cb;
    info.user_data = user_data;
    info.count = 0;

    rc_world_foreach_package (world,
                              RC_WORLD_ANY_CHANNEL,
                              match_package_fn,
                              &info);

    rcd_query_end (query_parts, query_packages_engine);

    return info.count;
}
