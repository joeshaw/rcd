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
#include <xmlrpc.h>
#include <libredcarpet.h>
#include "rcd-rpc.h"

typedef struct _RCDQueryEngine RCDQueryEngine;
struct _RCDQueryEngine {
    const char *key;

    gboolean  (*initialize) (RCDQueryPart *part);

    void      (*finalize)   (RCDQueryPart *part);

    gboolean  (*match)      (RCPackage    *package, 
                             RCDQueryPart *part);

    gboolean  (*quickstart) (RCWorld      *world,
                             RCDQueryPart *part,
                             GSList      **inital_list);

    gint        quickstart_score;
};

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

struct QueryTypeStrings {
    RCDQueryType type;
    const char *str;
};

struct QueryTypeStrings query2str[] = {
    { RCD_QUERY_IS,     "is" },
    { RCD_QUERY_SUBSTR, "substr" },
    { RCD_QUERY_LAST,   NULL }
};
        

RCDQueryType
rcd_query_type_from_string (const char *str)
{
    int i;
    g_return_val_if_fail (str && *str, RCD_QUERY_INVALID);
    for (i = 0; query2str[i].type != RCD_QUERY_LAST; ++i) {
        if (! g_strcasecmp (str, query2str[i].str))
            return query2str[i].type;
    }
    return RCD_QUERY_INVALID;
}

const char *
rcd_query_type_to_string (RCDQueryType type)
{
    int i;

    g_return_val_if_fail (type != RCD_QUERY_INVALID, "[Invalid]");
    g_return_val_if_fail (type != RCD_QUERY_LAST, "[Invalid:Last]");

    for (i = 0; query2str[i].type != RCD_QUERY_LAST; ++i) {
        if (query2str[i].type == type)
            return query2str[i].str;
    }

    return "[Invalid:NotFound]";
}

gboolean
rcd_query_type_compare (RCDQueryType type,
                        gint x, gint y)
{
    g_return_val_if_fail (type != RCD_QUERY_SUBSTR, FALSE);

    switch (type) {

    case RCD_QUERY_IS:
        return x == y;

    case RCD_QUERY_GT:
        return x > y;

    case RCD_QUERY_LT:
        return x < y;

    case RCD_QUERY_GT_EQ:
        return x >= y;

    case RCD_QUERY_LT_EQ:
        return x <= y;

    default:
    }

    g_assert_not_reached ();
    return FALSE;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static gboolean
bool_initialize (RCDQueryPart *part)
{
    return part->type == RCD_QUERY_IS
        && (!g_strcasecmp (part->query_str, "true") || !g_strcasecmp (part->query_str, "false"));
}

static gboolean
bool_match (gboolean val,
            RCDQueryPart *part)
{
    if (! g_strcasecmp (part->query_str, "true"))
        return val;

    if (! g_strcasecmp (part->query_str, "false"))
        return ! val;

    g_assert_not_reached ();
    return FALSE;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

/* Name matching */

static gboolean
name_initialize (RCDQueryPart *part)
{
    return part->type == RCD_QUERY_IS
        || part->type == RCD_QUERY_SUBSTR;
}

static gboolean
name_match (RCPackage *package,
            RCDQueryPart *part)
{
    if (part->type == RCD_QUERY_IS)
        return ! strcmp (package->spec.name, part->query_str);

    if (part->type == RCD_QUERY_SUBSTR)
        return strstr (package->spec.name, part->query_str) != NULL;

    g_assert_not_reached ();
    return FALSE;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

/* Summary matching */

static gboolean
summary_initialize (RCDQueryPart *part)
{
    return part->type == RCD_QUERY_IS
        || part->type == RCD_QUERY_SUBSTR;
}

static gboolean
summary_match (RCPackage *package,
               RCDQueryPart *part)
{
    if (part->type == RCD_QUERY_IS) /* Not very useful */
        return package->summary && ! strcmp (package->summary, part->query_str);

    if (part->type == RCD_QUERY_SUBSTR)
        return package->summary && strstr (package->summary, part->query_str) != NULL;

    g_assert_not_reached ();
    return FALSE;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

/* Description matching */

static gboolean
description_initialize (RCDQueryPart *part)
{
    return part->type == RCD_QUERY_IS 
        || part->type == RCD_QUERY_SUBSTR;
}

static gboolean
description_match (RCPackage *package,
                   RCDQueryPart *part)
{
    if (part->type == RCD_QUERY_IS) /* Not very useful */
        return package->description && ! strcmp (package->description, part->query_str);

    if (part->type == RCD_QUERY_SUBSTR)
        return package->description && strstr (package->description, part->query_str) != NULL;

    g_assert_not_reached ();
    return FALSE;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

/* Channel matching */

static gboolean
channel_initialize (RCDQueryPart *part)
{
    return part->type == RCD_QUERY_IS || part->type == RCD_QUERY_SUBSTR;
}

static gboolean
channel_match (RCPackage *package,
               RCDQueryPart *part)
{
    RCChannel *channel = package->channel;
    
    /* $ is a magic character for system packages.  This is very lame. */
    if (part->query_str[0] == '$' && part->query_str[1] == '\0') {
        return channel == NULL; 
    }
    
    if (channel) {
        gchar *endptr;
        guint32 id = strtoul (part->query_str, &endptr, 10);
        if (endptr == NULL) { /* yes, query_str was a uint */
            return rc_channel_get_id (channel) == id;
        }
    }

    if (part->type == RCD_QUERY_IS) {
        return ! strcmp (part->query_str, rc_channel_get_name (channel));
    }

    if (part->type == RCD_QUERY_SUBSTR) {
        return strstr (part->query_str, rc_channel_get_name (channel)) != NULL;
    }

    g_assert_not_reached ();
    return FALSE;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

/* Is installed? matching */

static gboolean
is_installed_match (RCPackage *package,
                    RCDQueryPart *part)
{
    return bool_match (rc_package_is_installed (package), part);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

/* Has Update? matching */

static gboolean
has_update_match (RCPackage *package,
                  RCDQueryPart *part)
{
    return bool_match (rc_package_get_best_upgrade (package) != NULL, part);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

/* Urgency matching */

static gboolean
urgency_initialize (RCDQueryPart *part)
{
    RCPackageImportance importance;

     if (part->type != RCD_QUERY_IS
         && part->type == RCD_QUERY_LT
         && part->type == RCD_QUERY_GT
         && part->type == RCD_QUERY_LT_EQ
         && part->type == RCD_QUERY_GT_EQ)
     return FALSE;

     importance = rc_string_to_package_importance (part->query_str);
     if (importance == RC_IMPORTANCE_INVALID
         || importance == RC_IMPORTANCE_LAST)
         return FALSE;

     part->data = GINT_TO_POINTER ((gint) importance);

     return TRUE;
}

static gboolean
urgency_match (RCPackage *package,
               RCDQueryPart *part)
{
    RCPackageUpdate *update;
    RCPackageImportance this_importance;
    int imp_num, this_imp_num;

    update = rc_package_get_latest_update (package);
    if (update == NULL)
        return FALSE;
    this_importance = update->importance;

    /* We negate these so that bigger numbers => greater urgency */
    imp_num = - GPOINTER_TO_INT (part->data);
    this_imp_num = - (gint) this_importance;

    return rcd_query_type_compare (part->type, this_imp_num, imp_num);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

/* Version matching */

static gboolean
version_initialize (RCDQueryPart *part)
{
    /* FIXME */
    g_assert_not_reached ();

    return FALSE;
}

static gboolean
version_match (RCPackage *package,
               RCDQueryPart *part)
{
    /* FIXME */

    return FALSE;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static RCDQueryEngine engines[] = {
    { "name",         name_initialize,        NULL, name_match,         NULL, 0 },
    { "summary",      summary_initialize,     NULL, summary_match,      NULL, 0 },
    { "description",  description_initialize, NULL, description_match,  NULL, 0 },
    { "channel",      channel_initialize,     NULL, channel_match,      NULL, 0 },
    { "is_installed", bool_initialize,        NULL, is_installed_match, NULL, 0 },
    { "has_update",   bool_initialize,        NULL, has_update_match,   NULL, 0 },
    { "urgency",      urgency_initialize,     NULL, urgency_match,      NULL, 0 },
    { "version",      version_initialize,     NULL, version_match,      NULL, 0 },
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

            if (parts[i].key == NULL) {
                g_warning ("Skipping part with NULL key");
                goto after_iteration;
            }

            if (parts[i].query_str == NULL) {
                g_warning ("Skipping part '%s' with NULL query string",
                           parts[i].key);
                goto after_iteration;
            }

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
            
            if (engine->initialize
                && ! engine->initialize (&parts[i])) {
                g_warning ("Skipping invalid part: %s %s %s",
                           parts[i].key, 
                           rcd_query_type_to_string (parts[i].type),
                           parts[i].query_str);
                goto after_iteration;
            }

            g_assert (engine->match);

            while (iter != NULL) {
                RCPackage *pkg = iter->data;
                gboolean match_val;

                next = iter->next;

                /* Check to see if this package matches the part's criteria.
                   If not, remove it from the list. */

                match_val = engine->match (pkg, &parts[i]);
                if (parts[i].negate)
                    match_val = ! match_val;

                if (! match_val)
                    matches = g_slist_delete_link (matches, iter);

                iter = next;
            }

        after_iteration:

            if (engine->finalize)
                engine->finalize (&parts[i]);
            
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

