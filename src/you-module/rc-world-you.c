/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rc-world-you.c
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

#include "rc-world-you.h"
#include <rc-world-system.h>
#include <rcd-world-remote.h>
#include <rcd-cache.h>
#include <rcd-transfer.h>
#include <rcd-transaction.h>

#include "wrapper.h"
#include "you-util.h"

static GQuark
rc_you_patches_quark (void)
{
    static GQuark quark;

    if (!quark)
        quark = g_quark_from_static_string ("rc_you_patches");

    return quark;
}

#define RC_YOU_PATCHES rc_you_patches_quark()

typedef struct _PatchInfo PatchInfo;
struct _PatchInfo {
    int          count;
    GQuark       nameq;
    RCChannel   *channel;
    RCPatchFn    callback;
    gpointer     user_data;
};

static gboolean
foreach_patch_cb (RCWorld *world, gpointer user_data)
{
    PatchInfo *info = user_data;
    RCYouPatchSList *list, *iter;

    list = g_object_get_qdata (G_OBJECT (world), RC_YOU_PATCHES);
    for (iter = list; iter; iter = iter->next) {
        RCYouPatch *patch = iter->data;

        if (!info->callback (patch, info->user_data)) {
            info->count = -1;
            return FALSE;
        }
        info->count++;
    }

    return TRUE;
}

gint
rc_world_multi_foreach_patch (RCWorldMulti *world,
                              RCPatchFn     callback,
                              gpointer      user_data)
{
    PatchInfo info;

    g_return_val_if_fail (callback != NULL, 0);

    info.callback = callback;
    info.count = 0;
    info.user_data = user_data;

    rc_world_multi_foreach_subworld (world,
                                     foreach_patch_cb,
                                     &info);

    return info.count;
}

typedef struct {
    RCYouPatch  *patch;
    RCChannel   *channel;
    GQuark       nameq;
} GetPatchInfo;

static gboolean
multi_get_patch_cb (RCYouPatch *patch, gpointer user_data)
{
    RCYouPatch **ret = user_data;

    *ret = patch;

    return FALSE;
}

RCYouPatch *
rc_world_multi_get_patch (RCWorldMulti *world,
                          RCChannel    *channel,
                          const char   *name)
{
    RCYouPatch *patch = NULL;

    g_return_val_if_fail (world != NULL, NULL);
    g_return_val_if_fail (channel != RC_CHANNEL_ANY
                          && channel != RC_CHANNEL_NON_SYSTEM, NULL);
    g_return_val_if_fail (name && *name, NULL);

    rc_world_multi_foreach_patch_by_name (world, name, channel,
                                          multi_get_patch_cb, &patch);
    return patch;
}

static gboolean
foreach_patch_by_name_cb (RCYouPatch *patch, gpointer user_data)
{
    PatchInfo *info = user_data;

    /* If channel matches and nameq is either not set or matches */
    if ((rc_channel_equal (info->channel, patch->channel)) &&
        (info->nameq == 0 || info->nameq == patch->spec.nameq)) {
        if (!info->callback (patch, info->user_data)) {
            info->count = -1;
            return FALSE;
        }
        info->count++;
    }

    return TRUE;
}

gint
rc_world_multi_foreach_patch_by_name (RCWorldMulti *world,
                                      const char   *name,
                                      RCChannel    *channel,
                                      RCPatchFn     callback,
                                      gpointer      user_data)

{
    PatchInfo info;

    info.count = 0;
    info.nameq = g_quark_from_string (name);
    info.channel = channel;
    info.callback = callback;
    info.user_data = user_data;

    rc_world_multi_foreach_patch (world, foreach_patch_by_name_cb, &info);

    return info.count;
}

typedef struct {
    RCYouPatch *patch;
    RCChannel *guess;
} GuessInfo;

static gboolean
guess_cb (RCYouPatch *patch, gpointer user_data)
{
    GuessInfo *info = user_data;

    if (!patch->channel)
        return TRUE;

    if (rc_package_spec_equal (RC_PACKAGE_SPEC (patch),
                               RC_PACKAGE_SPEC (info->patch))) {
        info->guess = patch->channel;
        return FALSE;
    }

    return TRUE;
}

RCChannel *
rc_world_multi_guess_patch_channel (RCWorldMulti *world, RCYouPatch *patch)
{
    GuessInfo info;

    g_return_val_if_fail (world != NULL, NULL);
    g_return_val_if_fail (patch != NULL, NULL);

    if (patch->channel != NULL &&
        !rc_channel_is_system (patch->channel) &&
        !rc_channel_is_hidden (patch->channel))
        return patch->channel;
    
    info.patch = patch;
    info.guess = NULL;

    rc_world_multi_foreach_patch_by_name
        (world, g_quark_to_string (patch->spec.nameq),
         RC_CHANNEL_NON_SYSTEM, guess_cb, &info);

    return info.guess;
}

static char *
rc_channel_get_patchinfo_file (RCDistro *distro, RCChannel *channel)
{
    gchar *sufix;
    char *info_file;

    g_return_val_if_fail (distro != NULL, NULL);
    g_return_val_if_fail (channel != NULL, NULL);

    sufix = rc_maybe_merge_paths ("getPatchList/", rc_distro_get_target (distro));
    info_file = rc_maybe_merge_paths (rc_channel_get_path (channel), sufix);

    g_free (sufix);

    return info_file;
}

static gboolean
fetch_patches_cb (RCYouPatch *patch, gpointer user_data)
{
    RCYouPatchSList **list = user_data;
    *list = g_slist_prepend (*list, rc_you_patch_ref (patch));
    
    return TRUE;
}

typedef struct {
    RCDWorldRemote *world;
    RCYouPatchSList *patches;
} FetchPatchesInfo;

gboolean
fetch_patches (RCChannel *channel, gpointer user_data)
{
    FetchPatchesInfo *info = user_data;
    RCDCacheEntry *entry;
    const GByteArray *data;
    gchar *info_file;
    gchar *url = NULL;
    RCDTransfer *t = NULL;
    const guint8 *buffer = NULL;
    gsize buffer_len = 0;

    if (rc_channel_get_type (channel) != RC_CHANNEL_TYPE_HELIX)
        goto cleanup;

    entry = rcd_cache_lookup (rcd_cache_get_normal_cache (),
                              "patch_list",
                              rc_channel_get_id (channel),
                              TRUE);

    info_file = rc_channel_get_patchinfo_file (info->world->distro, channel);
    if (info_file == NULL)
        goto cleanup;

    url = rc_maybe_merge_paths ((RC_WORLD_SERVICE (info->world))->url, info_file);
    g_free (info_file);

    t = rcd_transfer_new (url, RCD_TRANSFER_FLAGS_NONE, entry);
    data = rcd_transfer_begin_blocking (t);

    if (rcd_transfer_get_error (t)) {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Unable to download patch list: %s",
                  rcd_transfer_get_error_string (t));
        goto cleanup;
    }

    buffer = data->data;
    buffer_len = data->len;

    g_assert (buffer != NULL);

    rc_extract_patches_from_helix_buffer (buffer, buffer_len,
                                          channel,
                                          fetch_patches_cb,
                                          &(info->patches));
cleanup:
    g_free (url);

    if (t)
        g_object_unref (t);

    return TRUE;
}

static void
free_patches (gpointer data)
{
    RCYouPatchSList *patches = (RCYouPatchSList *) data;

    rc_you_patch_slist_unref (patches);
    g_slist_free (patches);
}

void
rc_world_add_patches (RCWorld *world, gpointer user_data)
{
    RCYouPatchSList *patches = NULL;

    if (RC_IS_WORLD_SYSTEM (world)) {
        RCChannel *channel = RC_WORLD_SYSTEM (world)->system_channel;

        patches = rc_you_wrapper_get_installed_patches (channel);
    } else if (RCD_IS_WORLD_REMOTE (world) &&
               RCD_WORLD_REMOTE (world)->premium_service) {
        FetchPatchesInfo info;

        info.world = RCD_WORLD_REMOTE (world);
        info.patches = NULL;
        rc_world_foreach_channel (world,
                                  fetch_patches,
                                  &info);
        patches = info.patches;
    }

    if (patches) {
        g_object_set_qdata_full (G_OBJECT (world),
                                 RC_YOU_PATCHES,
                                 patches,
                                 free_patches);
        rc_world_touch_package_sequence_number (world);
    }
}
