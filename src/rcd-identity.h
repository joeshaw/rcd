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

#include "rcd-privileges.h"

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

gboolean     rcd_identity_well_formed_username (const char *str);

gboolean     rcd_identity_well_formed_password (const char *str);

gboolean     rcd_identity_password_file_is_secure (void);

guint        rcd_identity_get_sequence_number (void);

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

typedef struct _RCDIdentityBackend RCDIdentityBackend;

typedef RCDIdentity *(*RCDIdentityLookupFn)  (RCDIdentityBackend *backend,
                                              const char         *username);
typedef void         (*RCDIdentityForeachFn) (RCDIdentityBackend *backend,
                                              RCDIdentityFn       fn,
                                              gpointer            user_data);
typedef gboolean     (*RCDIdentityUpdateFn)  (RCDIdentityBackend *backend,
                                              RCDIdentity        *id);
typedef gboolean     (*RCDIdentityRemoveFn)  (RCDIdentityBackend *backend,
                                              RCDIdentity        *id);

struct _RCDIdentityBackend {
    gboolean is_editable;
    gpointer user_data;

    RCDIdentityLookupFn  lookup_fn;
    RCDIdentityForeachFn foreach_fn;
    RCDIdentityUpdateFn  update_fn;  /* Only needed if is_editable is TRUE */
    RCDIdentityRemoveFn  remove_fn;  /* Only needed if is_editable is TRUE */
};

RCDIdentityBackend *rcd_identity_backend_new (gboolean is_editable);

void      rcd_identity_add_backend    (RCDIdentityBackend *backend);
gboolean  rcd_identity_remove_backend (RCDIdentityBackend *backend);

RCDIdentity *rcd_identity_lookup (const char    *username);

void         rcd_identity_foreach (gboolean       editable_only,
                                   RCDIdentityFn  fn,
                                   gpointer       user_data);

/* If the identity already exists, replace the current entry with the one
   contained in the RCDIdentity.  Otherwise just add it to the file. */
gboolean     rcd_identity_update  (RCDIdentity   *identity);

gboolean     rcd_identity_remove  (RCDIdentity   *identity);

#endif /* __RCD_IDENTITY_H__ */

