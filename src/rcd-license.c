/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-license.c
 *
 * Copyright (C) 2003 Ximian, Inc.
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
#include "rcd-news.h"

#include <stdlib.h>

#include <libredcarpet.h>
#include <xml-util.h>

static GHashTable *rcd_licenses = NULL;

gboolean
rcd_license_parse (const char *data, gsize size)
{
    xmlDoc *doc;
    xmlNode *node;
    GHashTable *licenses;

    g_return_val_if_fail (data != NULL, FALSE);

    doc = rc_uncompress_xml (data, size);
    if (doc == NULL) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Couldn't parse license XML file");
        return FALSE;
    }

    node = xmlDocGetRootElement (doc);
    if (node == NULL || g_ascii_strcasecmp (node->name, "licenses") != 0) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL, "License XML file is not valid");
        xmlFreeDoc (doc);
        return FALSE;
    }

    licenses = g_hash_table_new_full (rc_str_case_hash, rc_str_case_equal,
                                      g_free, g_free);

    /* Descend to the actual licenses */
    for (node = node->xmlChildrenNode; node; node = node->next) {
        char *name;
        char *text;
        
        /* Text node, we're not interested */
        if (node->type == XML_TEXT_NODE)
            continue;

        if (g_ascii_strcasecmp (node->name, "license") != 0) {
            rc_debug (RC_DEBUG_LEVEL_WARNING,
                      "Unknown tag '%s' where 'license' was expected",
                      node->name);
            continue;
        }

        name = xml_get_prop (node, "name");
        text = xml_get_content (node);

        if (name && !*name) {
            g_free (name);
            name = NULL;
        }

        if (text && !*text) {
            g_free (text);
            text = NULL;
        }

        if (name && !text) {
            rc_debug (RC_DEBUG_LEVEL_WARNING,
                      "Ignoring license '%s' with name but no text", name);
        }
        else if (text && !name) {
            rc_debug (RC_DEBUG_LEVEL_WARNING,
                      "Ignoring license has text but no name");
        }
        else if (!text && !name) {
            rc_debug (RC_DEBUG_LEVEL_WARNING,
                      "Ignoring license with not name or text");
        }
        else {
            g_hash_table_replace (licenses, name, text);
            rc_debug (RC_DEBUG_LEVEL_INFO, "Added license '%s'", name);
        }
    }

    xmlFreeDoc (doc);

    if (rcd_licenses)
        g_hash_table_destroy (rcd_licenses);
    rcd_licenses = licenses;

    return TRUE;
}

const char *
rcd_license_lookup (const char *name)
{
    g_return_val_if_fail (name != NULL, NULL);

    if (!rcd_licenses)
        return NULL;

    return g_hash_table_lookup (rcd_licenses, name);
}

static void
hash_to_list (gpointer key, gpointer value, gpointer user_data)
{
    GSList **list = user_data;

    *list = g_slist_prepend (*list, value);
}

GSList *
rcd_license_lookup_from_package_slist (RCPackageSList *packages)
{
    GHashTable *licenses;
    GSList *iter;
    GSList *license_list;

    if (!packages)
        return NULL;

    licenses = g_hash_table_new (rc_str_case_hash, rc_str_case_equal);

    for (iter = packages; iter; iter = iter->next) {
        RCPackage *package = iter->data;
        RCPackageUpdate *update = rc_package_get_latest_update (package);
        const char *license_text;

        if (!update || !update->license)
            continue;

        if (g_hash_table_lookup (licenses, update->license))
            continue;

        license_text = rcd_license_lookup (update->license);

        if (license_text)
            g_hash_table_insert (licenses, update->license,
                                 (char *) license_text);
    }

    license_list = NULL;
    g_hash_table_foreach (licenses, hash_to_list, &license_list);
    g_hash_table_destroy (licenses);

    return license_list;
}
