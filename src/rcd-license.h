/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-license.h
 *
 * Copyright (C) 2003 Ximian, Inc.
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

#ifndef __RCD_LICENSE_H__
#define __RCD_LICENSE_H__

#include <libredcarpet.h>

#include "rcd-world-remote.h"

/* This takes compressed XML data */
gboolean    rcd_license_parse                     (RCDWorldRemote *remote,
                                                   const char     *data,
                                                   gsize           size);

GSList     *rcd_license_lookup_from_package_slist (RCPackageSList *packages);

#endif /* __RCD_LICENSE_H__ */

