/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-services.c
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
#include "rcd-services.h"

#include <libredcarpet.h>

#include "rcd-prefs.h"

#define SERVICES_PATH "/var/lib/rcd"
#define SERVICES_FILE SERVICES_PATH "/services.xml"

#define SYNTH_DB_PATH "/var/lib/rcd"
#define SYNTH_DB_FILE SYNTH_DB_PATH "/synthetic-packages.xml"

#define DEFAULT_HOST_URL "http://red-carpet.ximian.com"

void
rcd_services_load (RCWorldMulti *multi)
{
    static gboolean loaded = FALSE;
    RCWorld *world;
    xmlDoc *doc;
    xmlNode *node;

    if (loaded) {
        rc_debug (RC_DEBUG_LEVEL_ERROR, "Cannot load services more than once");
        return;
    }
    
    loaded = TRUE;


    /* Create our default services */
    world = rc_world_service_mount ("system:///");
    RC_WORLD_SERVICE (world)->is_unsaved = TRUE;
    rc_world_multi_add_subworld (multi, world);
    g_object_unref (world);

    world = rc_world_service_mount ("synthetic:" SYNTH_DB_FILE);
    RC_WORLD_SERVICE (world)->is_unsaved = TRUE;
    rc_world_multi_add_subworld (multi, world);
    g_object_unref (world);

    
    if (!g_file_test (SERVICES_FILE, G_FILE_TEST_EXISTS)) {
        const char *default_url;

        /* For compatibility with pre-2.0 rcds */
        default_url = rcd_prefs_get_string ("/Network/host=" DEFAULT_HOST_URL);

        world = rc_world_service_mount (default_url);
        rc_world_multi_add_subworld (multi, world);
        g_object_unref (world);

        rcd_services_save ();

        return;
    }

    doc = xmlParseFile (SERVICES_FILE);
    if (doc == NULL) {
        rc_debug (RC_DEBUG_LEVEL_ERROR, "Can't parse services file '%s'",
                  SERVICES_FILE);
        return;
    }

    node = xmlDocGetRootElement (doc);
    for (node = node->xmlChildrenNode; node; node = node->next) {
        char *url;

        if (!xml_node_match (node, "service"))
            continue;

        url = xml_get_value (node, "url");

        if (!url) {
            rc_debug (RC_DEBUG_LEVEL_WARNING, "Service missing URL");
            continue;
        }

        world = rc_world_service_mount (url);
        rc_world_multi_add_subworld (multi, world);
        g_object_unref (world);
    }
}

static void
save_mount_cb (RCWorldService *service, gpointer user_data)
{
    xmlNode *root = user_data;
    xmlNode *node;
    xmlNode *sub_node;

    if (service->is_unsaved)
        return;

    node = xmlNewChild (root, NULL, "service", NULL);
    sub_node = xmlNewChild (node, NULL, "url", service->url);
}

void
rcd_services_save (void)
{
    xmlDoc *doc;
    xmlNode *root;

    if (!g_file_test (SERVICES_PATH, G_FILE_TEST_EXISTS)) {
        if (rc_mkdir (SERVICES_PATH, 0755)) {
            rc_debug (RC_DEBUG_LEVEL_ERROR,
                      "Unable to create directory '"SERVICES_PATH"' to save "
                      "services data");
            return;
        }
    }

    root = xmlNewNode (NULL, "services");

    doc = xmlNewDoc ("1.0");
    xmlDocSetRootElement (doc, root);

    rc_world_service_foreach_mount (save_mount_cb, root);

    if (!xmlSaveFile (SERVICES_FILE, doc)) {
        rc_debug (RC_DEBUG_LEVEL_ERROR, "Unable to save services data to "
                  "'"SERVICES_FILE"'");
    }

    xmlFreeDoc (doc);
}
    
