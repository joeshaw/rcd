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

#ifdef RC_PACKAGE_FIND_LEAKS
static GHashTable *leaked_patches = NULL;
#endif

RCYouPatch *
rc_you_patch_new (void)
{
    RCYouPatch *patch = g_new0 (RCYouPatch, 1);

    patch->arch = RC_ARCH_UNKNOWN;
    patch->refs = 1;

#ifdef RC_PACKAGE_FIND_LEAKS
    if (leaked_patches == NULL)
        leaked_patches = g_hash_table_new (NULL, NULL);

    g_hash_table_insert (leaked_patches, patch, patch);
#endif

    return patch;
}

void
rc_you_patch_free (RCYouPatch *patch)
{
    rc_package_spec_free_members ((RCPackageSpec *) patch);
    g_free (patch->product);
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

#ifdef RC_PACKAGE_FIND_LEAKS
    g_assert (leaked_patches);
    g_hash_table_remove (leaked_patches, patch);
#endif

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

GSList *
rc_you_patch_slist_lookup_licenses (RCYouPatchSList *list)
{
    RCYouPatchSList *iter;
    GSList *licenses = NULL;

    for (iter = list; iter; iter = iter->next) {
        RCYouPatch *patch = iter->data;

        if (patch->license)
            licenses = g_slist_prepend (licenses, patch->license);
    }

    return licenses;
}

#ifdef RC_PACKAGE_FIND_LEAKS
static void
leaked_pkg_cb (gpointer key, gpointer val, gpointer user_data)
{
    RCYouPatch *pkg = key;

    g_print (">!> Leaked %s (refs=%d)\n",
             rc_package_spec_to_str_static (RC_PACKAGE_SPEC (pkg)),
             pkg->refs);
}
#endif

void
rc_patch_spew_leaks (void)
{
#ifdef RC_PACKAGE_FIND_LEAKS
    if (leaked_patches) 
        g_hash_table_foreach (leaked_patches,
                              leaked_pkg_cb,
                              NULL);
#endif
}
