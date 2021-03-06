/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-query-packages.c
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
#include "rcd-query-packages.h"

#include <stdlib.h>

static gboolean
name_match (RCDQueryPart *part,
            gpointer      data)
{
    RCPackage *pkg = data;
    return rcd_query_match_string_ci (
        part, g_quark_to_string (pkg->spec.nameq));
}

static gboolean
summary_match (RCDQueryPart *part,
            gpointer      data)
{
    RCPackage *pkg = data;

    if (!pkg->summary)
        return FALSE;

    return rcd_query_match_string_ci (part, pkg->summary);
}

static gboolean
description_match (RCDQueryPart *part,
                   gpointer      data)
{
    RCPackage *pkg = data;

    if (!pkg->description)
        return FALSE;

    return rcd_query_match_string_ci (part, pkg->description);
}

static gboolean
text_match (RCDQueryPart *part,
            gpointer      data)
{
    RCPackage *pkg = data;

    return rcd_query_match_string_ci (
        part, g_quark_to_string (pkg->spec.nameq))
        || (pkg->summary && rcd_query_match_string_ci (part, pkg->summary))
        || (pkg->description && rcd_query_match_string_ci (part,
                                                           pkg->description));
}

static gboolean
channel_match (RCDQueryPart *part,
               gpointer      data) 
{
    RCPackage *pkg = data;

    return rc_channel_equal_id (pkg->channel, part->query_str);
}

static gboolean
installed_match (RCDQueryPart *part,
                 gpointer      data)
{
    RCPackage *pkg = data;
    return rcd_query_match_bool (part, rc_package_is_installed (pkg));
}

static gboolean
name_installed_match (RCDQueryPart *part,
                      gpointer      data)
{
    RCPackage *pkg = data;
    RCPackage *sys_pkg = rc_world_get_package (
        rc_get_world (), 
        RC_CHANNEL_SYSTEM,
        g_quark_to_string (pkg->spec.nameq));

    return rcd_query_match_bool (part, sys_pkg != NULL);
} /* name_installed_match */

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

struct InstalledCheck {
    RCPackage *pkg;
    gboolean installed;
};

static gboolean
installed_check_cb (RCPackage *sys_pkg,
                    gpointer user_data)
{
    struct InstalledCheck *check = user_data;
   
    if (check->installed)
        return FALSE;

    if (rc_package_spec_equal (RC_PACKAGE_SPEC (sys_pkg),
                               RC_PACKAGE_SPEC (check->pkg)))
        check->installed = TRUE;

    return TRUE;
}

static gboolean
package_installed_match (RCDQueryPart *part,
                         gpointer      data)
{
    RCPackage *pkg = data;
    gboolean installed;


    if (rc_package_is_installed (pkg)) {
        
        installed = TRUE;

    } else {
        struct InstalledCheck check;
        const char *name;

        check.pkg = pkg;
        check.installed = FALSE;

        name = g_quark_to_string (RC_PACKAGE_SPEC (pkg)->nameq);
        rc_world_foreach_package_by_name (rc_get_world (),
                                          name,
                                          RC_CHANNEL_SYSTEM,
                                          installed_check_cb,
                                          &check);

        installed = check.installed;
    }

    return rcd_query_match_bool (part, installed);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static gboolean
needs_upgrade_match (RCDQueryPart *part,
                   gpointer      data)
{
    RCPackage *pkg = data;
    return rcd_query_match_bool (part,
                                 rc_package_is_installed (pkg) /* must be installed */
                                 && rc_world_get_best_upgrade (rc_get_world (), pkg, TRUE) != NULL);
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
    if (rc_package_is_installed (pkg))
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

    { "text", /* name or summary or description */
      NULL, NULL, NULL,
      text_match },

    { "channel",
      NULL, NULL, NULL,
      channel_match },

    { "installed",  /* This is a system package, essentially. */
      rcd_query_validate_bool, NULL, NULL,
      installed_match },

    { "name-installed", /* Any package by this name installed */
      rcd_query_validate_bool, NULL, NULL,
      name_installed_match },

    /* This package is a system package, or appears to be the
       in-channel version of an installed package. */
    { "package-installed",  
      rcd_query_validate_bool, NULL, NULL,
      package_installed_match },

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

static gboolean
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

    return TRUE;
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
                              RC_CHANNEL_ANY,
                              match_package_fn,
                              &info);

    rcd_query_end (query_parts, query_packages_engine);

    return info.count;
}
