/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rc-you-package.h
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

#ifndef __RC_YOU_PACKAGE__
#define __RC_YOU_PACKAGE__

#include <glib.h>
#include "rc-you-file.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _RCYouPackage RCYouPackage;
typedef GSList RCYouPackageSList;

struct _RCYouPackage {
    gint       refs;
    RCYouFile *base_package;
    GSList    *patch_rpm_based_on;
    RCYouFile *patch_rpm;
    guint32    patch_rpm_size;
    guint32    patch_rpm_dlsize;
};

RCYouPackage      *rc_you_package_new         (void);
void               rc_you_package_free        (RCYouPackage *package);
RCYouPackage      *rc_you_package_ref         (RCYouPackage *package);
void               rc_you_package_unref       (RCYouPackage *package);
RCYouPackageSList *rc_you_package_slist_ref   (RCYouPackageSList *list);
void               rc_you_package_slist_unref (RCYouPackageSList *list);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /*__RC_YOU_PACKAGE__ */
