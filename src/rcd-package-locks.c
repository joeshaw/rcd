/* This is -*- C -*- */
/* vim: set sw=2: */
/* $Id$ */

/*
 * rcd-package-locks.c
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
#include "rcd-package-locks.h"

#include <stdio.h>

#define PACKAGE_LOCK_PATH "/var/lib/rcd"
#define PACKAGE_LOCK_NAME "/package-locks.xml"
#define PACKAGE_LOCK_FILE PACKAGE_LOCK_PATH PACKAGE_LOCK_NAME

void
rcd_package_locks_load (RCWorld *world)
{
  xmlDoc *doc;
  xmlNode *root, *iter;

  if (! g_file_test (PACKAGE_LOCK_FILE, G_FILE_TEST_EXISTS))
    return;

  doc = xmlParseFile (PACKAGE_LOCK_FILE);
  if (doc == NULL) {
    rc_debug (RC_DEBUG_LEVEL_WARNING,
	      "Can't read package locks from file '"
	      PACKAGE_LOCK_FILE "'");
    return;
  }

  root = xmlDocGetRootElement (doc);

  if (g_strcasecmp (root->name, "locks")) {
    rc_debug (RC_DEBUG_LEVEL_WARNING,
	      "'" PACKAGE_LOCK_FILE "' doesn't look like it "
	      "actually contains lock XML.");
  } else {
	  for (iter = root->xmlChildrenNode; iter != NULL; iter = iter->next) {
		  RCPackageMatch *match = rc_package_match_from_xml_node (iter);
		  if (match)
			  rc_world_add_lock (world, match);
	  }
  }

  xmlFreeDoc (doc);
}

static gboolean
write_lock_cb (RCPackageMatch *match,
	       gpointer        user_data)
{
  xmlNode *root = user_data;
  xmlNode *node;
  
  node = rc_package_match_to_xml_node (match);
  xmlAddChild (root, node);
  return TRUE;
}

void
rcd_package_locks_save (RCWorld *world)
{
  xmlDoc *doc;
  xmlNode *root;

  doc = xmlNewDoc ("1.0");
  root = xmlNewNode(NULL, "locks");
  xmlDocSetRootElement (doc, root);

  rc_world_foreach_lock (world, write_lock_cb, root);

  if (! xmlSaveFile (PACKAGE_LOCK_FILE, doc)) {
    rc_debug (RC_DEBUG_LEVEL_WARNING,
	      "Can't write package locks to '" PACKAGE_LOCK_FILE "'");
  }
  
  xmlFreeDoc (doc);
}

