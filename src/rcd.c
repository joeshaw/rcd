/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd.c
 *
 * Copyright (C) 2002 Ximian, Inc.
 *
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
#include <glib.h>

#include <libredcarpet.h>

#include "rcd-query.h"

static void
rcd_query_fn (RCPackage *package, gpointer user_data)
{
    g_print ("%s\n", rc_package_to_str_static (package));
}

static void
rcd_query_test (void)
{
    RCDQueryPart parts[3];

    /* Query for all packages that mention 'GNOME' in the summary but
       don't have 'gnome' in the package name. */

    parts[0].key = "summary";
    parts[0].type = RCD_QUERY_SUBSTR;
    parts[0].query_str = "GNOME";
    parts[0].negate = FALSE;

    parts[1].key = "name";
    parts[1].type = RCD_QUERY_SUBSTR;
    parts[1].query_str = "gnome";
    parts[1].negate = TRUE;

    parts[2].type = RCD_QUERY_LAST;

    rcd_query (rc_get_world (),
               parts,
               rcd_query_fn,
               NULL);
}

int
main (int argc, char *argv[])
{
    RCWorld *world;
    RCPackman *packman;

    g_type_init ();

    /* Create a packman, hand it off to the world */
    world = rc_get_world ();
    packman = rc_distman_new ();
    rc_world_register_packman (world, packman);
    rc_world_get_system_packages (world);

    rcd_query_test ();

    return 0;
}
