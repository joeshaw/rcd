/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rc-you-query.c
 *
 * Copyright (C) 2004 Novell, Inc.
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
#include "rc-you-query.h"

#include <stdlib.h>

static gboolean
name_match (RCDQueryPart *part,
            gpointer      data)
{
    RCYouPatch *patch = data;
    return rcd_query_match_string_ci (
        part, g_quark_to_string (patch->spec.nameq));
}

static gboolean
summary_match (RCDQueryPart *part,
               gpointer      data)
{
    RCYouPatch *patch = data;

    if (!patch->summary)
        return FALSE;

    return rcd_query_match_string_ci (part, patch->summary);
}

static gboolean
description_match (RCDQueryPart *part,
                   gpointer      data)
{
    RCYouPatch *patch = data;

    if (!patch->description)
        return FALSE;

    return rcd_query_match_string_ci (part, patch->description);
}

static gboolean
text_match (RCDQueryPart *part,
            gpointer      data)
{
    RCYouPatch *patch = data;

    return rcd_query_match_string_ci (
        part, g_quark_to_string (patch->spec.nameq))
        || (patch->summary && rcd_query_match_string_ci (part, patch->summary))
        || (patch->description && rcd_query_match_string_ci (part,
                                                             patch->description));
}

static gboolean
channel_match (RCDQueryPart *part,
               gpointer      data) 
{
    RCYouPatch *patch = data;

    return rc_channel_equal_id (patch->channel, part->query_str);
}

static gboolean
installed_match (RCDQueryPart *part,
                 gpointer      data)
{
    RCYouPatch *patch = data;
    return rcd_query_match_bool (part, patch->installed);
}

static gboolean
name_installed_match (RCDQueryPart *part,
                      gpointer      data)
{
    RCYouPatch *patch = data;
    RCYouPatch *sys_patch = rc_world_multi_get_patch
        (RC_WORLD_MULTI (rc_get_world ()),
         RC_CHANNEL_SYSTEM,
         g_quark_to_string (patch->spec.nameq));

    return rcd_query_match_bool (part, sys_patch != NULL);
} /* name_installed_match */

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

struct InstalledCheck {
    RCYouPatch *patch;
    gboolean installed;
};

static gboolean
installed_check_cb (RCYouPatch *sys_patch,
                    gpointer user_data)
{
    struct InstalledCheck *check = user_data;
   
    if (check->installed)
        return FALSE;

    if (rc_package_spec_equal (RC_PACKAGE_SPEC (sys_patch),
                               RC_PACKAGE_SPEC (check->patch)))
        check->installed = TRUE;

    return TRUE;
}

static gboolean
patch_installed_match (RCDQueryPart *part,
                       gpointer      data)
{
    RCYouPatch *patch = data;
    gboolean installed;

    if (patch->installed) {
        installed = TRUE;
    } else {
        struct InstalledCheck check;
        const char *name;

        check.patch = patch;
        check.installed = FALSE;

        name = g_quark_to_string (RC_PACKAGE_SPEC (patch)->nameq);
        rc_world_multi_foreach_patch_by_name (RC_WORLD_MULTI (rc_get_world ()),
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
    RCYouPatch *patch = data;

    /* Installed packages automatically fail. */
    if (patch->installed)
        return FALSE;

    return rcd_query_type_int_compare (part->type,
                                       GPOINTER_TO_INT (part->data),
                                       (gint) patch->importance);
}


/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static RCDQueryEngine query_patches_engine[] = {
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

    { "installed",  /* This is a system patch, essentially. */
      rcd_query_validate_bool, NULL, NULL,
      installed_match },

    { "name-installed", /* Any patch by this name installed */
      rcd_query_validate_bool, NULL, NULL,
      name_installed_match },

    /* This patch is a system patch, or appears to be the
       in-channel version of an installed package. */
    { "patch-installed",  
      rcd_query_validate_bool, NULL, NULL,
      patch_installed_match },

    { "importance",
      importance_validate, NULL, NULL,
      importance_match },

    { NULL, NULL, NULL, NULL, NULL }
};

struct QueryInfo {
    RCDQueryPart *query_parts;
    RCPatchFn    matching_patch_cb;
    gpointer      user_data;
    gint          count;
};

static gboolean
match_patch_fn (RCYouPatch *patch, gpointer user_data)
{
    struct QueryInfo *info = user_data;

    if (rcd_query_match (info->query_parts, 
                         query_patches_engine, 
                         patch)) {
        
        if (info->matching_patch_cb)
            info->matching_patch_cb (patch, info->user_data);

        ++info->count;
    }

    return TRUE;
}

gint
rc_you_query_patches (RCWorld      *world,
                      RCDQueryPart *query_parts,
                      RCPatchFn     matching_patch_cb,
                      gpointer      user_data)
{
    struct QueryInfo info;

    g_return_val_if_fail (world != NULL, -1);

    if (! rcd_query_begin (query_parts, query_patches_engine))
        return -1;

    info.query_parts = query_parts;
    info.matching_patch_cb = matching_patch_cb;
    info.user_data = user_data;
    info.count = 0;

    rc_world_multi_foreach_patch (RC_WORLD_MULTI (world),
                                  match_patch_fn,
                                  &info);

    rcd_query_end (query_parts, query_patches_engine);

    return info.count;
}
