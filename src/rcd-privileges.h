/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-privileges.h
 *
 * Copyright (C) 2002 Ximian, Inc.
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

#ifndef __RCD_PRIVILEGES_H__
#define __RCD_PRIVILEGES_H__

#include <glib.h>

typedef guint64 RCDPrivileges;
typedef void (*RCDPrivilegesFn) (RCDPrivileges priv,
                                 const char   *priv_name,
                                 gpointer      user_data);

RCDPrivileges rcd_privileges_register    (const char *priv_name);

void          rcd_privileges_foreach     (RCDPrivilegesFn fn,
                                          gpointer       user_data);

RCDPrivileges rcd_privileges_from_string (const char *priv_name);

char         *rcd_privileges_to_string   (RCDPrivileges priv);

void          rcd_privileges_init        (void);

#endif /* __RCD_PRIVILEGES_H__ */
