/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-identity.h
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

#ifndef __RCD_IDENTITY_H__
#define __RCD_IDENTITY_H__

#include <glib.h>

#include <rcd-privileges.h>

typedef struct _RCDIdentity RCDIdentity;

typedef void (*RCDIdentityFn) (RCDIdentity *, gpointer);

struct _RCDIdentity {
    gchar *username;
    gchar *password;
    RCDPrivileges privileges;
};

RCDIdentity *rcd_identity_new  (void);

RCDIdentity *rcd_identity_copy (RCDIdentity *id);

void         rcd_identity_free (RCDIdentity *id);

gboolean     rcd_identity_approve_action (RCDIdentity  *id,
                                          RCDPrivileges required_priv);

void         rcd_identity_foreach_from_password_file (RCDIdentityFn fn,
                                                      gpointer user_data);

RCDIdentity *rcd_identity_from_password_file (const char *username);

/* If the identity already exists in the password file, replace the current
   entry with the one contained in the RCDIdentity.  Otherwise just add it
   to the file. */
gboolean     rcd_identity_update_password_file (RCDIdentity *id);

gboolean     rcd_identity_remove_from_password_file (const char *username);

#endif /* __RCD_IDENTITY_H__ */

