/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-query.c
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
#include "rcd-query.h"

#include <glib.h>

typedef struct _RCDQueryEngine RCDQueryEngine;
struct _RCDQueryEngine {
    const char *key;

    gboolean  (*valid_type) (RCDQueryType type);
    gboolean  (*valid_str)  (RCDQueryType type,
                             const char *query_str);
    gboolean  (*match)      (RCPackage  *package, 
                             RCDQueryType type,
                             const char *query_str);
    gboolean  (*quickstart) (RCDQueryPart *part, GSList **);

    gint        quickstart_score;
};

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static gboolean
bool_valid_type (RCDQueryType type)
{
    return type == RCD_QUERY_IS;
}

static gboolean
bool_valid_str (RCDQueryType type,
                const char *query_str)
{
    return !g_strcasecmp (query_str, "true") || !g_strcasecmp (query_str, "false");
}

static gboolean
bool_match (gboolean val,
            RCDQueryType type,
            const char *query_str)
{
    if (! g_strcasecmp (query_str, "true"))
        return val;

    if (! g_strcasecmp (query_str, "false"))
        return ! val;

    g_assert_not_reached ();
    return FALSE;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

/* Name matching */

static gboolean
name_valid_type (RCDQueryType type)
{
    return type == RCD_QUERY_IS || type == RCD_QUERY_SUBSTR;
}

static gboolean
name_match (RCPackage *package,
            RCDQueryType type,
            const char *query_str)
{
    if (type == RCD_QUERY_IS)
        return ! strcmp (package->spec.name, query_str);

    if (type == RCD_QUERY_SUBSTR)
        return strstr (package->spec.name, query_str) != NULL;

    g_assert_not_reached ();
    return FALSE;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

/* Summary matching */

static gboolean
summary_valid_type (RCDQueryType type)
{
    return type == RCD_QUERY_IS || type == RCD_QUERY_SUBSTR;
}

static gboolean
summary_match (RCPackage *package,
               RCDQueryType type,
               const char *query_str)
{
    if (type == RCD_QUERY_IS) /* Not very useful */
        return package->summary && ! strcmp (package->summary, query_str);

    if (type == RCD_QUERY_SUBSTR)
        return package->summary && strstr (package->summary, query_str) != NULL;

    g_assert_not_reached ();
    return FALSE;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

/* Description matching */

static gboolean
description_valid_type (RCDQueryType type)
{
    return type == RCD_QUERY_IS || type == RCD_QUERY_SUBSTR;
}

static gboolean
description_match (RCPackage *package,
                   RCDQueryType type,
                   const char *query_str)
{
    if (type == RCD_QUERY_IS) /* Not very useful */
        return package->description && ! strcmp (package->description, query_str);

    if (type == RCD_QUERY_SUBSTR)
        return package->description && strstr (package->description, query_str) != NULL;

    g_assert_not_reached ();
    return FALSE;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

/* Is installed? matching */

static gboolean
is_installed_match (RCPackage *package,
                    RCDQueryType type,
                    const char *query_str)
{
    return bool_match (rc_package_is_installed (package), type, query_str);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

/* Has Update? matching */

static gboolean
has_update_match (RCPackage *package,
                  RCDQueryType type,
                  const char *query_str)
{
    return bool_match (rc_package_get_best_upgrade (package) != NULL, type, query_str);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static RCDQueryEngine engines[] = {
    { "name", name_valid_type, NULL, name_match, NULL, 0 },
    { "summary", summary_valid_type, NULL, summary_match, NULL, 0 },
    { "description", description_valid_type, NULL, description_match, NULL, 0 },
    { "is_installed", bool_valid_type, bool_valid_str, is_installed_match, NULL, 0 },
    { "has_update", bool_valid_type, bool_valid_str, has_update_match, NULL, 0 },
    { NULL, NULL, NULL, NULL, NULL, 0 }
};


void
build_slist_fn (RCPackage *pkg, gpointer user_data)
{
    GSList **slist = user_data;
    *slist = g_slist_prepend (*slist, pkg);
}

gint
rcd_query (RCWorld     *world,
           RCDQueryPart *parts,
           RCPackageFn  fn,
           gpointer     user_data)
{
    gint i, j, count;
    GSList *matches = NULL, *iter, *next;

    g_return_val_if_fail (world != NULL, -1);
    g_return_val_if_fail (parts != NULL, -1);

    for (i = 0; parts[i].type != RCD_QUERY_LAST; ++i)
        parts[i].processed = FALSE;

    /* Build an initial match list */

    rc_world_foreach_package (world,
                              RC_WORLD_ANY_CHANNEL,
                              build_slist_fn,
                              &matches);

    /* Step through our query parts, using each to trim our
       match list. */

    for (i = 0; parts[i].type != RCD_QUERY_LAST && matches != NULL; ++i) {
        
        if (! parts[i].processed) {

            RCDQueryEngine *engine = NULL;

            /* Find a matching engine, using a crappy linear search */
            for (j = 0; engines[j].key != NULL && engine == NULL; ++j) {
                if (! g_strcasecmp (parts[i].key, engines[j].key))
                    engine = &engines[j];
            }

            iter = matches;

            if (engine == NULL) {
                g_warning ("Skipping unknown key '%s'", parts[i].key);
                goto after_iteration;
            }

            if (engine->valid_type 
                && ! engine->valid_type (parts[i].type)) {
                g_warning ("Skipping invalid type: %s %d %s",
                           parts[i].key, parts[i].type, parts[i].query_str);
                goto after_iteration;
            }

            if (engine->valid_str
                && ! engine->valid_str (parts[i].type, parts[i].query_str)) {
                g_warning ("Skipping invalid query str: %s %d %s",
                           parts[i].key, parts[i].type, parts[i].query_str);
                goto after_iteration;
            }

            g_assert (engine->match);

            while (iter != NULL) {
                RCPackage *pkg = iter->data;
                gboolean match_val;

                next = iter->next;

                /* Check to see if this package matches the part's criteria.
                   If not, remove it from the list. */

                match_val = engine->match (pkg, parts[i].type, parts[i].query_str);
                if (parts[i].negate)
                    match_val = ! match_val;

                if (! match_val)
                    matches = g_slist_delete_link (matches, iter);

                iter = next;
            }

        after_iteration:
            
            parts[i].processed = TRUE;
        }
    }

    /* Iterate across the remaining matches, invoking our callback on each. */

    count = 0;
    for (iter = matches; iter != NULL; iter = iter->next) {
        RCPackage *pkg = iter->data;
        fn (pkg, user_data);
        ++count;
    }
    
    g_slist_free (matches);

    return count;
}
