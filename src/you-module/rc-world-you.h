/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rc-world-you.h
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

#ifndef __RC_WORLD_YOU__
#define __RC_WORLD_YOU__

#include <glib.h>
#include <rc-world-multi.h>
#include <rc-channel.h>
#include "rc-you-patch.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef gboolean (*RCPatchFn) (RCYouPatch *patch, gpointer user_data);

gint rc_world_multi_foreach_patch (RCWorldMulti *world,
                                   RCPatchFn     callback,
                                   gpointer      user_data);

RCYouPatch *rc_world_multi_get_patch (RCWorldMulti *world,
                                      RCChannel    *channel,
                                      const char   *name);

void rc_world_add_patches         (RCWorld *world, gpointer user_data);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __RC_WORLD_YOU__ */
