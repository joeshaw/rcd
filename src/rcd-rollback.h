/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-rollback.h
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

#ifndef __RCD_ROLLBACK_H__
#define __RCD_ROLLBACK_H__

#include <libredcarpet.h>

void rcd_rollback_add_package       (RCPackage      *package);
void rcd_rollback_add_package_slist (RCPackageSList *packages);

RCPackage      *rcd_rollback_get_package_by_name (const char *name);
RCPackageSList *rcd_rollback_get_packages        (void);

#endif /* __RCD_ROLLBACK_H__ */

