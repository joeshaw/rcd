/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * rcd-subscriptions.c: Code for managing subscriptions
 *
 * Copyright (c) 2000, 2001 Ximian, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 */

#include <config.h>
#include "rcd-subscriptions.h"

#include <stdlib.h>

#define SUBSCRIPTIONS_PATH "/var/lib/redcarpet"
#define SUBSCRIPTIONS_FILE "/var/lib/redcarpet/subscriptions.xml"

void
rcd_subscriptions_load (void)
{
    xmlDoc *doc;
    xmlNode *root;

    if (! g_file_test (SUBSCRIPTIONS_FILE, G_FILE_TEST_EXISTS))
        return;

    doc = xmlParseFile (SUBSCRIPTIONS_FILE);
    if (doc == NULL) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Can't open subscriptions file '%s'\n",
                  SUBSCRIPTIONS_FILE);
        return;
    }

    root = xmlDocGetRootElement (doc);
    rc_world_import_subscriptions_from_xml (rc_get_world (), root);

    xmlFreeDoc (doc);
}

void
rcd_subscriptions_save (void)
{
    xmlDoc *doc;
    xmlNode *root;

    if (! g_file_test (SUBSCRIPTIONS_PATH, G_FILE_TEST_EXISTS)) {
        if (rc_mkdir (SUBSCRIPTIONS_PATH, 0755)) {
            rc_debug (RC_DEBUG_LEVEL_WARNING,
                      "Unable to create directory '%s' for subscriptions file",
                      SUBSCRIPTIONS_PATH);
            return;
        }
    }

    doc = xmlNewDoc ("1.0");
    root = rc_world_export_subcriptions_to_xml (rc_get_world ());
    xmlDocSetRootElement (doc, root);

    xmlSaveFile(SUBSCRIPTIONS_FILE, doc);
    xmlFreeDoc(doc);
}
