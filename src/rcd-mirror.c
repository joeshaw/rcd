/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-mirror.c
 *
 * Copyright (C) 2003 Ximian, Inc.
 *
 */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
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
#include "rcd-mirror.h"

#include <xml-util.h>

RCDMirror *
rcd_mirror_parse (xmlNode *node)
{
  RCDMirror *mirror;

  g_return_val_if_fail (node != NULL, NULL);

  if (g_strcasecmp (node->name, "mirror"))
    return NULL;

  mirror = g_new0 (RCDMirror, 1);

  mirror->name     = xml_get_value (node, "name");
  mirror->location = xml_get_value (node, "location");
  mirror->url      = xml_get_value (node, "url");
  mirror->ftp      = xml_get_value (node, "ftp");
  mirror->contact  = xml_get_value (node, "contact");

  /* Silently ignore any mirrors w/o a name or url. */
  if (! (mirror->name && *mirror->name && mirror->url && *mirror->url)) {
      rcd_mirror_free (mirror);
      return NULL;
  }

  return mirror;
}

void
rcd_mirror_free (RCDMirror *mirror)
{
  if (mirror) {
    g_free (mirror->name);
    g_free (mirror->location);
    g_free (mirror->url);
    g_free (mirror->ftp);
    g_free (mirror->contact);
    g_free (mirror);
  }
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static GSList *mirror_slist = NULL;

void
rcd_mirror_add (RCDMirror *mirror)
{
  g_return_if_fail (mirror != NULL);
  mirror_slist = g_slist_prepend (mirror_slist, mirror);
}

void
rcd_mirror_clear (void)
{
  GSList *iter;

  for (iter = mirror_slist; iter != NULL; iter = iter->next) {
    RCDMirror *mirror = iter->data;
    rcd_mirror_free (mirror);
  }
  g_slist_free (mirror_slist);
  mirror_slist = NULL;
}

void
rcd_mirror_foreach (RCDMirrorFn fn, gpointer user_data)
{
  GSList *iter;
  g_return_if_fail (fn != NULL);

  for (iter = mirror_slist; iter != NULL; iter = iter->next) {
    fn ((RCDMirror *) iter->data, user_data);
  }
}
