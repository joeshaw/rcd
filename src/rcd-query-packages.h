/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-query-packages.h
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

#ifndef __RCD_QUERY_PACKAGES_H__
#define __RCD_QUERY_PACKAGES_H__

#include <libredcarpet.h>
#include "rcd-query.h"

gint rcd_query_packages (RCWorld      *world,
                         RCDQueryPart *query_parts,
                         RCPackageFn   matching_package_cb,
                         gpointer      user_data);

#endif /* __RCD_QUERY_PACKAGES_H__ */

