/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-identity.h
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

#ifndef __RCD_IDENTITY_H__
#define __RCD_IDENTITY_H__

#include <glib.h>

typedef struct _RCDIdentity RCDIdentity;

struct _RCDIdentity {
    gchar *username;
    gchar *password;

    int privileges;
};

RCDIdentity *rcd_identity_new  (void);

void         rcd_identity_free (RCDIdentity *id);

RCDIdentity *rcd_identity_from_password_file (const char *username);

#endif /* __RCD_IDENTITY_H__ */

