/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rc-you-patch.h
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

#ifndef __RC_YOU_PATCH__
#define __RC_YOU_PATCH__

#include <glib.h>
#include <rc-arch.h>
#include <rc-channel.h>
#include <rc-package-spec.h>
#include "rc-you-file.h"
#include "rc-you-package.h"


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _RCYouPatch RCYouPatch;
typedef GSList RCYouPatchSList;

struct _RCYouPatch {
    RCPackageSpec spec;

    gchar *product;
    RCYouFile *file;

    gint refs;

    RCArch arch;
    guint32 buildtime;
    guint32 size;

    RCChannel *channel;

    RCYouPackageSList *packages;
    RCPackageImportance importance;

    gchar *license;

    RCYouFile *pre_script;
    RCYouFile *post_script;

    gchar *summary;
    gchar *description;

    guint installed    : 1;
    guint install_only : 1;
};

RCYouPatch      *rc_you_patch_new         (void);
void             rc_you_patch_free        (RCYouPatch *patch);
RCYouPatch      *rc_you_patch_ref         (RCYouPatch *patch);
void             rc_you_patch_unref       (RCYouPatch *patch);
RCYouPatchSList *rc_you_patch_slist_ref   (RCYouPatchSList *list);
void             rc_you_patch_slist_unref (RCYouPatchSList *list);

GSList          *rc_you_patch_slist_lookup_licenses (RCYouPatchSList *list);
         
void             rc_patch_spew_leaks (void);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /*__RC_YOU_PATCH__ */
