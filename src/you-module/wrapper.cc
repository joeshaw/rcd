/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * wrapper.cc
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

#include "wrapper.h"

#include <rc-util.h>
#include <rc-world.h>
#include <rc-debug.h>

#include <Y2PM.h>

#include <y2pm/PMManager.h>
#include <y2pm/PMYouSettings.h>
#include <y2pm/PMYouPatch.h>
#include <y2pm/PMPackage.h>
#include <y2pm/PMYouPatchInfo.h>
#include <y2pm/PMYouPatchManager.h>
#include <y2pm/PMYouProduct.h>
#include <y2pm/InstYou.h>
#include <y2pm/InstTarget.h>

#include "you-util.h"

#define INSTALLED_YOU_PATH "/var/lib/YaST2/you/installed"

extern "C" {

static const char *
rc_you_string_to_char (const std::string str)
{
    return str.c_str ();
}

static RCPackageImportance
rc_you_kind_to_rc_importance (PMYouPatch::Kind kind)
{
    RCPackageImportance imp;

    switch (kind) {
    case PMYouPatch::kind_security:    imp = RC_IMPORTANCE_URGENT;    break;
    case PMYouPatch::kind_recommended: imp = RC_IMPORTANCE_SUGGESTED; break;
    case PMYouPatch::kind_optional:    imp = RC_IMPORTANCE_FEATURE;   break;
    case PMYouPatch::kind_patchlevel:
    case PMYouPatch::kind_document:    imp = RC_IMPORTANCE_MINOR;     break;

    default:
                                       imp = RC_IMPORTANCE_INVALID;   break;
    }

    return imp;
}

static gboolean
rc_you_solvable_to_rc_package_spec (RCPackageSpec *spec, PMSolvablePtr solvable)
{
    const char *name;

    name = rc_you_string_to_char (solvable->name ());
    spec->nameq = g_quark_from_string (name);

    /* When the patch name starts with "patch-", then yasty
       doesn't parse it's name and version. For example:
       'patch-9250' has name 'patch-9250' and version '0'.

       There's only one thing left to say: *sigh* */

    if (g_str_has_prefix (name, "patch-")) {
        int i;
        gchar **pieces = g_strsplit (name, "-", 0);

        /* Find the last piece */
        for (i = 0; pieces[i + 1]; i++)
            ;

        spec->version = g_strdup (pieces[i]);
        spec->release = g_strdup ("");

        g_strfreev (pieces);
    } else {
        PkgEdition edition = solvable->edition ();

        spec->version = g_strdup (rc_you_string_to_char (edition.version ()));
        spec->release = g_strdup (rc_you_string_to_char (edition.release ()));

        if (edition.has_epoch ()) {
            spec->has_epoch = 1;
            spec->epoch = edition.epoch ();
        }
    }

    return TRUE;
}

static RCYouPatch *
rc_you_patch_from_yast_patch (PMYouPatchPtr source)
{
    RCYouPatch *patch;
    const char *script;

    patch = rc_you_patch_new ();
    patch->arch = rc_arch_from_string (rc_you_string_to_char (source->arch ()));

    rc_you_solvable_to_rc_package_spec ((RCPackageSpec *) patch, (PMSolvablePtr) source);
    patch->importance = rc_you_kind_to_rc_importance (source->kind ());
    patch->size = (guint32) source->patchSize ();
    patch->channel = RC_CHANNEL_SYSTEM;

    patch->summary = g_strdup (rc_you_string_to_char (source->shortDescription ()));
    patch->description = g_strdup (rc_you_string_to_char (source->longDescription ()));

    script = rc_you_string_to_char (source->preScript ());
    if (script && strlen (script) > 0)
        patch->pre_script = rc_you_file_new (script);

    script = rc_you_string_to_char (source->postScript ());
    if (script && strlen (script) > 0)
        patch->post_script = rc_you_file_new (script);

    return patch;
}

void
rc_you_wrapper_install_patches (RCYouPatchSList  *list,
                                GError          **error)
{
    PMManager::PMSelectableVec::const_iterator it;
    PMError err;
    PMYouSettingsPtr settings = new PMYouSettings ();
    PMYouPatchInfoPtr patch_info = new PMYouPatchInfo (settings);
    PMYouServer server;

    settings->setLangCode (LangCode ("en"));
    settings->setReloadPatches (false);
    settings->setCheckSignatures (false);
    settings->setDryRun (false);
    settings->setNoExternalPackages (true);
    settings->setGetAll (false);
    settings->setGetOnly (false);

    InstYou you (patch_info, settings);
    you.initProduct ();

    server.setUrl (TMP_YOU_PATH);
    settings->setPatchServer (server);

    you.retrievePatchDirectory();
    you.retrievePatchInfo();
    you.selectPatches (PMYouPatch::kind_all);

    for (it = Y2PM::youPatchManager ().begin ();
         it != Y2PM::youPatchManager ().end (); ++it) {
        GSList *iter;
        PMYouPatchPtr you_patch;
        RCYouPatch *patch;
        gboolean install = FALSE;

        you_patch = (*it)->theObject ();
        patch = rc_you_patch_from_yast_patch (you_patch);

        for (iter = list; iter; iter = iter->next) {
            RCYouPatch *iter_patch = (RCYouPatch *) iter->data;

            if (rc_package_spec_equal (RC_PACKAGE_SPEC (iter_patch),
                                       RC_PACKAGE_SPEC (patch))) {
                install = TRUE;
                break;
            }
        }

        if (install) {
            rc_debug (RC_DEBUG_LEVEL_INFO,
                      "Installing patch %s",
                      rc_package_spec_to_str_static (RC_PACKAGE_SPEC (patch)));
            (*it)->user_set_install ();
        } else
            (*it)->user_unset ();

        rc_you_patch_unref (patch);
    }

    err = you.processPatches ();
    if (err) {
        gchar *buf = g_strdup_printf ("%s (%s)",
                                      rc_you_string_to_char (err.errstr ()),
                                      rc_you_string_to_char (err.details ()));
        g_set_error (error, RC_ERROR, RC_ERROR, buf);
        g_free (buf);
    }

    settings = NULL;
    patch_info = NULL;
}

static RCYouPatchSList *
read_installed_patches (PMYouPatchInfoPtr patch_info,
                        RCChannel *channel)
{
    GDir *dir;
    const gchar *filename;
    RCYouPatchSList *list = NULL;
    GError *error = NULL;

    if (!g_file_test (INSTALLED_YOU_PATH,
                      (GFileTest)(G_FILE_TEST_EXISTS | G_FILE_TEST_IS_DIR)))
        return NULL;

    dir = g_dir_open (INSTALLED_YOU_PATH, 0, &error);
    if (error) {
        rc_debug (RC_DEBUG_LEVEL_ERROR,
                  "Can not read installed patches: %s",
                  error->message);
        g_error_free (error);
        return NULL;
    }

    while ((filename = g_dir_read_name (dir))) {
        PMError you_error;
        PMYouPatchPtr you_patch;
        RCYouPatch *patch;

        you_error = patch_info->readFile (INSTALLED_YOU_PATH,
                                          filename,
                                          you_patch);
        if (you_error) {
            rc_debug (RC_DEBUG_LEVEL_ERROR,
                      "Ignoring installed patch '%s': %s (%s)",
                      filename,
                      rc_you_string_to_char (you_error.errstr ()),
                      rc_you_string_to_char (you_error.details ()));
            continue;
        }

        patch = rc_you_patch_from_yast_patch (you_patch);
        you_patch = NULL;
        if (patch) {
            patch->installed = TRUE;
            patch->channel = rc_channel_ref (channel);
            list = g_slist_prepend (list, patch);
        }
    }

    g_dir_close (dir);

    return list;
}

RCYouPatchSList *
rc_you_wrapper_get_installed_patches (RCChannel *channel)
{
    RCYouPatchSList *list;
    PMYouSettingsPtr settings = new PMYouSettings ();
    PMYouPatchInfoPtr patch_info = new PMYouPatchInfo (settings);

    list = read_installed_patches (patch_info, channel);

    settings = NULL;
    patch_info = NULL;

    return list;
}

void
rc_you_wrapper_products_foreach (SuseProductCallback callback, gpointer user_data)
{
    PMYouSettingsPtr settings = new PMYouSettings ();
    PMYouPatchInfoPtr patchInfo = new PMYouPatchInfo (settings);

    InstYou you (patchInfo, settings);
    you.initProduct ();

    std::list<PMYouProductPtr> products = you.settings ()->products();

    std::list<PMYouProductPtr>::const_iterator itProd;
    for (itProd = products.begin (); itProd != products.end (); ++itProd) {
        PMYouProductPtr prod = *itProd;

        if (callback)
            if (!callback (rc_you_string_to_char (prod->product ()),
                           rc_you_string_to_char (prod->version ()),
                           rc_you_string_to_char (prod->baseArch ()),
                           prod->businessProduct () ? TRUE : FALSE,
                           rc_you_string_to_char (prod->patchPath ().asString ()),
                           user_data))
                break;
    }

    settings = NULL;
    patchInfo = NULL;
}

}
