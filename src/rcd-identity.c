/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-identity.c
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
#include <libredcarpet.h>
#include "rcd-auth.h"
#include "rcd-identity.h"

RCDIdentity *
rcd_identity_new (void)
{
    RCDIdentity *id;

    id = g_new0 (RCDIdentity, 1);

    return id;
}

void
rcd_identity_free (RCDIdentity *id)
{
    if (id) {
        g_free (id->username);
        g_free (id);
    }
}

RCDIdentity *
rcd_identity_from_password_file (const char *username)
{
    RCBuffer *buffer;
    char **lines;
    char **l;
    RCDIdentity *id = NULL;

    g_return_val_if_fail (username, NULL);

    buffer = rc_buffer_map_file (SYSCONFDIR "/rc-passwd");

    if (!buffer)
        return NULL;

    lines = g_strsplit (buffer->data, "\n", 0);
    for (l = lines; *l; l++) {
        char **user_info;

        /* The line begins with a #, so it's a comment */
        if (**l == '#')
            continue;

        user_info = g_strsplit (*l, ":", 0);
        if (!user_info[0] || !user_info[1] || !user_info[2] ||
            strcmp (user_info[0], username) != 0) {
            g_strfreev (user_info);
            continue;
        }

        g_print ("username: %s\n"
                 "password: %s\n"
                 "actions: %s\n",
                 user_info[0], user_info[1], user_info[2]);

        id = rcd_identity_new ();
        id->username = g_strdup (user_info[0]);
        id->password = g_strdup (user_info[1]);
        id->privileges = rcd_string_to_auth_action_list (user_info[2]);

        g_strfreev (user_info);
        break;
    }

    g_strfreev (lines);

    rc_buffer_unmap_file(buffer);

    return id;
} /* rcd_identity_from_password_file */
