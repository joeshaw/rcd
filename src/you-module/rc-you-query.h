/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rc-you-query.h
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

#ifndef __RC_YOU_QUERY_H__
#define __RC_YOU_QUERY_H__

#include <libredcarpet.h>
#include "rcd-query.h"
#include "rc-world-you.h"

gint rc_you_query_patches (RCWorld      *world,
                           RCDQueryPart *query_parts,
                           RCPatchFn     matching_patch_cb,
                           gpointer      user_data);

#endif /* __RC_YOU_QUERY_H__ */
