/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * suse-product.h
 *
 * Copyright (C) 2004 Novell, Inc.
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

#ifndef __SUSE_PRODUCT__
#define __SUSE_PRODUCT__

#include <glib.h>

void suse_product_initialize (void);
void suse_product_finalize   (void);

const gchar *suse_product_get_patchdir  (const gchar *product);
const gchar *suse_product_get_rpmdir    (const gchar *product);
const gchar *suse_product_get_scriptdir (const gchar *product);

#endif /*__SUSE_PRODUCT__ */
