/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-rollback.c
 *
 * Copyright (C) 2002 Ximian, Inc.
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

#include <config.h>
#include "rcd-rollback.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "rcd-prefs.h"

static gboolean loaded = FALSE;
static RCPackageSList *rollback_packages = NULL;

static void
load_packages (void)
{
    RCWorld *world;
    RCPackman *packman;
    char *manifest_file;
    RCBuffer *buf;
    int i;
    char *c;
    RCPackage *package;

    world = rc_get_world ();
    packman = rc_world_get_packman (world);

    if (!packman) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "No packman associated with the world.");
        return;
    }

    rc_package_slist_unref (rollback_packages);
    rollback_packages = NULL;

    manifest_file = g_strconcat (rcd_prefs_get_cache_dir (),
                                 "/repackage/manifest.list", NULL);

    if (!g_file_test (manifest_file, G_FILE_TEST_EXISTS)) {
        /* If it's not there, no big deal.  Just exit quietly. */
        goto cleanup;
    }
        

    buf = rc_buffer_map_file (manifest_file);
    
    if (!buf) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Unable to read rollback manifest '%s'", manifest_file);
        goto cleanup;
    }

    c = (char *) buf->data;
    i = 0;
    while (i < buf->size) {
        int start = i;
        char *pname = NULL;
        char *pfile = NULL;

        while (i < buf->size && *c != ':') {
            if (*c == '\n')
                break;
            else {
                c++;
                i++;
            }
        }

        if (*c == ':') {
            pname = g_strndup (buf->data + start, i - start);

            /* Move past the colon */
            c++;
            i++;
        }
        else {
            /* Malformed line.  Drop it. */
            /* Move past the newline */
            c++;
            i++;

            continue;
        }

        start = i;
        while (i < buf->size && *c != '\n') {
            c++;
            i++;
        }

        pfile = g_strndup (buf->data + start, i - start);

        if (*c == '\n') {
            /* Move past the newline */
            c++;
            i++;
        }

        package = rc_packman_query_file (packman, pfile);

        if (package) {
            package->package_filename = pfile;
            rollback_packages = g_slist_prepend (rollback_packages, package);
        }
        else
            g_free (pfile);

        g_free (pname);
    }

    loaded = TRUE;

cleanup:
    g_free (manifest_file);
}

static void
save_packages (void)
{
    char *manifest_file;
    int fd;
    GSList *iter;

    manifest_file = g_strconcat (rcd_prefs_get_cache_dir (),
                                 "/repackage/manifest.list", NULL);

    fd = open (manifest_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    if (fd < 0) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Can't open rollback manifest file '%s'", manifest_file);
        goto cleanup;
    }

    for (iter = rollback_packages; iter; iter = iter->next) {
        RCPackage *p = iter->data;
        char *str;

        str = g_strconcat (g_quark_to_string (RC_PACKAGE_SPEC (p)->nameq),
                           ":", p->package_filename, "\n", NULL);
        rc_write (fd, str, strlen (str));
    }

cleanup:
    g_free (manifest_file);
} /* save_packages */

static void
add_package (RCPackage *package)
{
    RCPackage *p;

    if ((p = rc_package_spec_slist_find_name (
             rollback_packages,
             g_quark_to_string (RC_PACKAGE_SPEC (package)->nameq))))
    {
        rollback_packages = g_slist_remove (rollback_packages, p);
        rc_package_unref (p);
    }

    rollback_packages = g_slist_prepend (rollback_packages,
                                         rc_package_ref (package));
} /* add_package */

void
rcd_rollback_add_package (RCPackage *package)
{
    if (!loaded)
        load_packages ();

    add_package (package);
    save_packages ();
} /* rcd_rollback_add_package */

void
rcd_rollback_add_package_slist (RCPackageSList *packages)
{
    RCPackageSList *iter;

    if (!loaded)
        load_packages ();

    for (iter = packages; iter; iter = iter->next) {
        add_package ((RCPackage *) iter->data);
    }

    save_packages ();
} /* rcd_rollback_add_package_slist */

RCPackage *
rcd_rollback_get_package_by_name (const char *name)
{
    if (!loaded)
        load_packages ();

    return rc_package_spec_slist_find_name (rollback_packages, name);
} /* rcd_rollback_get_package_by_name */

RCPackageSList *
rcd_rollback_get_packages (void)
{
    if (!loaded)
        load_packages ();

    return rollback_packages;
} /* rcd_rollback_get_packages */
