/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * wrapper.h
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

#ifndef _RC_YOU_WRAPPER_H
#define _RC_YOU_WRAPPER_H

#include <glib.h>
#include "rc-you-patch.h"
#include "rc-pending.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef gboolean (*SuseProductCallback) (const gchar *name,
                                         const gchar *version,
                                         const gchar *arch,
                                         gboolean business,
                                         const gchar *patch_path,
                                         gpointer user_data);

RCYouPatchSList *rc_you_wrapper_get_installed_patches (RCChannel *channel);
void rc_you_wrapper_install_patches (RCYouPatchSList  *list,
                                     RCPending        *transaction_pending,
                                     RCPending        *transaction_step_pending,
                                     GError          **error);

void rc_you_wrapper_products_foreach (SuseProductCallback, gpointer user_data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _RC_YOU_WRAPPER_H */
