/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rc-you-package.c
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

#include "rc-you-package.h"

RCYouPackage *
rc_you_package_new (void)
{
    RCYouPackage *package = g_new0 (RCYouPackage, 1);

    package->refs = 1;

    return package;
}

void
rc_you_package_free (RCYouPackage *package)
{
    if (package->base_package)
        rc_you_file_unref (package->base_package);

#if 0
    /* This is not used righ now (and probably never will) */
    if (package->patch_rpm_based_on) {
        g_slist_foreach (package->patch_rpm_based_on,
                         G_FUNC (g_free),
                         NULL);
        g_slist_free (package->patch_rpm_based_on);
    }
#endif

    if (package->patch_rpm)
        rc_you_file_unref (package->patch_rpm);

    g_free (package);
}

RCYouPackage *
rc_you_package_ref (RCYouPackage *package)
{
    if (package) {
        g_assert (package->refs > 0);
        ++package->refs;
    }

    return package;
}

void
rc_you_package_unref (RCYouPackage *package)
{
    if (package) {

        g_assert (package->refs > 0);
        --package->refs;

        if (package->refs == 0)
            rc_you_package_free (package);
    }
}

RCYouPackageSList *
rc_you_package_slist_ref (RCYouPackageSList *list)
{
    g_slist_foreach (list, (GFunc) rc_you_package_ref, NULL);

    return list;
}

void
rc_you_package_slist_unref (RCYouPackageSList *list)
{
    GSList *iter;

    for (iter = list; iter; iter = iter->next)
        rc_you_package_unref ((RCYouPackage *) iter->data);
}
