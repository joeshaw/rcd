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

#include <Y2PM.h>

#include <y2pm/PMManager.h>
#include <y2pm/PMYouSettings.h>
#include <y2pm/PMYouPatch.h>
#include <y2pm/PMPackage.h>
#include <y2pm/PMYouPatchInfo.h>
#include <y2pm/PMYouPatchManager.h>
#include <y2pm/InstYou.h>

extern "C" {

static gchar *
rc_you_string_to_char (const std::string str)
{
    return g_strdup (str.c_str ());
}

static gchar *
rc_you_ustring_to_char (Ustring ustr)
{
    return rc_you_string_to_char (ustr.asString ());
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
    PkgEdition edition;

    edition = solvable->edition ();

    spec->nameq = g_quark_from_string (rc_you_string_to_char (solvable->name ()));
    spec->version = g_strdup (rc_you_string_to_char (edition.version ()));
    spec->release = g_strdup (rc_you_string_to_char (edition.release ()));

    if (edition.has_epoch ()) {
        spec->has_epoch = 1;
        spec->epoch = edition.epoch ();
    }

    return TRUE;
}

static RCYouPatch *
rc_you_patch_from_selectable (PMSelectablePtr selectable)
{
    PMYouPatchPtr source = selectable->theObject ();
    RCYouPatch *patch;
    const gchar *script;

    patch = rc_you_patch_new ();
    patch->arch = rc_arch_from_string (rc_you_string_to_char (source->arch ()));

    rc_you_solvable_to_rc_package_spec ((RCPackageSpec *) patch, (PMSolvablePtr) source);
    patch->importance = rc_you_kind_to_rc_importance (source->kind ());
    patch->size = (guint32) source->patchSize ();
    patch->channel = RC_CHANNEL_SYSTEM;

    patch->summary = g_strdup (rc_you_string_to_char (source->shortDescription ()));
    patch->description = g_strdup (rc_you_string_to_char (source->longDescription ()));

    patch->installed = selectable->has_installed ();

    script = rc_you_string_to_char (source->preScript ());
    if (script && strlen (script) > 0)
        patch->pre_script = rc_you_file_new (script);

    script = rc_you_string_to_char (source->postScript ());
    if (script && strlen (script) > 0)
        patch->post_script = rc_you_file_new (script);

    /* FIXME: This should probably be deleted altogether */
#if 0    
    std::list<PMPackagePtr> packages = source->packages ();
    std::list<PMPackagePtr>::const_iterator itPkg;
    for (itPkg = packages.begin (); itPkg != packages.end (); itPkg++) {
        RCPackageSpec spec;
        RCYouPatchPackageInfo info;
        int ret;

        rc_you_solvable_to_rc_package_spec (&spec, (PMSolvablePtr) *itPkg);
        info.patch = patch;
        info.spec = &spec;

        ret = rc_world_foreach_package_by_name (rc_get_world (),
                                                g_quark_to_string (spec.nameq),
                                                patch->channel,
                                                you_patch_add_package,
                                                &info);
        if (ret != -1) {
            /* foreach loop was not short-circuit'ed, that means
               the package was not found. We don't like incomplete
               patches */
            g_print ("Can not find package %s, ignoring patch %s",
                     rc_package_spec_to_str_static (&spec),
                     rc_package_spec_to_str_static ((RCPackageSpec *) patch));
            rc_you_patch_unref (patch);
            patch = NULL;
            break;
        }
    }
#endif    

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
    settings->setDryRun (false); /* FIXME: Set this to false if you dare! */
    settings->setNoExternalPackages (true);
    settings->setGetAll (false);
    settings->setGetOnly (false);

    InstYou you (patch_info, settings);
    you.initProduct ();

    server.setUrl ("/tmp/lib/YaST2/you/mnt");
    settings->setPatchServer (server);

    you.retrievePatchDirectory();
    you.retrievePatchInfo();
    you.selectPatches (PMYouPatch::kind_all);

    for (it = Y2PM::youPatchManager ().begin ();
         it != Y2PM::youPatchManager ().end (); ++it) {
        GSList *iter;
        guint nameq = g_quark_from_string (rc_you_ustring_to_char ((*it)->name ()));
        gboolean install = FALSE;

        for (iter = list; iter; iter = iter->next) {
            RCYouPatch *patch = (RCYouPatch *) iter->data;

            if (nameq == patch->spec.nameq) {
                if (!(*it)->has_installed ())
                    install = TRUE;
                break;
            }
        }

        if (install) {
            g_print ("Installing patch %s\n", g_quark_to_string (nameq));
            (*it)->user_set_install ();
        } else
            (*it)->user_unset ();
    }

    err = you.processPatches ();
    if (err) {
        gchar *buf = g_strdup_printf ("%s (%s)", 
                                      rc_you_string_to_char (err.errstr ()),
                                      rc_you_string_to_char (err.details ()));
        g_set_error (error, RC_ERROR, RC_ERROR, buf);
        g_free (buf);
    }
}

RCYouPatchSList *
rc_you_wrapper_get_installed_patches (void)
{
    RCYouPatchSList *list = NULL;
    PMYouSettingsPtr settings = new PMYouSettings ();
    PMYouPatchInfoPtr patch_info = new PMYouPatchInfo (settings);
    PMYouServer server;

    settings->setLangCode (LangCode ("en"));
    settings->setReloadPatches (true);
    settings->setCheckSignatures (false);
    settings->setDryRun (true);
    settings->setNoExternalPackages (false);
    settings->setGetAll (true);
    settings->setGetOnly (true);

    InstYou you (patch_info, settings);
    you.initProduct ();

    server.setUrl (""); /* Only list installed patches */
    settings->setPatchServer (server);

    you.retrievePatchDirectory();
    you.retrievePatchInfo();
    you.selectPatches (PMYouPatch::kind_all);

    PMManager::PMSelectableVec::const_iterator it;
    for (it = Y2PM::youPatchManager().begin();
         it != Y2PM::youPatchManager().end(); it++) {
        RCYouPatch *patch = rc_you_patch_from_selectable (*it);

        if (patch && (*it)->has_installed ())
            list = g_slist_prepend (list, patch);
    }

    list = g_slist_reverse (list);

    return list;
}

}
