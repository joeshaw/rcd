/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rc-you-patch.c
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

#include "rc-you-patch.h"

RCYouPatch *
rc_you_patch_new (void)
{
    RCYouPatch *patch = g_new0 (RCYouPatch, 1);

    patch->arch = RC_ARCH_UNKNOWN;
    patch->refs = 1;

    return patch;
}

void
rc_you_patch_free (RCYouPatch *patch)
{
    rc_package_spec_free_members ((RCPackageSpec *) patch);
    g_free (patch->summary);
    g_free (patch->description);
    g_free (patch->license);

    if (patch->file)
        rc_you_file_unref (patch->file);
    if (patch->pre_script)
        rc_you_file_unref (patch->pre_script);
    if (patch->post_script)
        rc_you_file_unref (patch->post_script);

    rc_you_package_slist_unref (patch->packages);
    g_slist_free (patch->packages);

    rc_channel_unref (patch->channel);

    g_free (patch);
}

RCYouPatch *
rc_you_patch_ref (RCYouPatch *patch)
{
    if (patch) {
        g_assert (patch->refs > 0);
        ++patch->refs;
    }

    return patch;
}

void
rc_you_patch_unref (RCYouPatch *patch)
{
    if (patch) {

        g_assert (patch->refs > 0);
        --patch->refs;

        if (patch->refs == 0)
            rc_you_patch_free (patch);
    }
}

RCYouPatchSList *
rc_you_patch_slist_ref (RCYouPatchSList *list)
{
    g_slist_foreach (list, (GFunc) rc_you_patch_ref, NULL);

    return list;
}

void
rc_you_patch_slist_unref (RCYouPatchSList *list)
{
    GSList *iter;

    for (iter = list; iter; iter = iter->next)
        rc_you_patch_unref ((RCYouPatch *) iter->data);
}
