/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rc-you-file.c
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

#include "rc-you-file.h"

RCYouFile *
rc_you_file_new (const gchar *filename)
{
    RCYouFile *file;

    g_return_val_if_fail (filename != NULL, NULL);

    file = g_new0 (RCYouFile, 1);

    file->filename = g_strdup (filename);
    file->refs = 1;

    return file;
}

void
rc_you_file_set_url (RCYouFile *file, gchar *url)
{
    g_return_if_fail (file != NULL);

    g_free (file->url);
    file->url = url;
}

void
rc_you_file_set_local_path (RCYouFile *file, gchar *path)
{
    g_return_if_fail (file != NULL);

    g_free (file->local_path);
    file->local_path = path;
}

void
rc_you_file_free (RCYouFile *file)
{
    g_return_if_fail (file != NULL);

    g_free (file->filename);
    g_free (file->url);
    g_free (file->local_path);

    g_free (file);
}

RCYouFile *
rc_you_file_ref (RCYouFile *file)
{
    if (file) {
        g_assert (file->refs > 0);
        ++file->refs;
    }

    return file;
}

void
rc_you_file_unref (RCYouFile *file)
{
    if (file) {

        g_assert (file->refs > 0);
        --file->refs;

        if (file->refs == 0)
            rc_you_file_free (file);
    }
}

RCYouFileSList *
rc_you_file_slist_ref (RCYouFileSList *list)
{
    g_slist_foreach (list, (GFunc) rc_you_file_ref, NULL);

    return list;
}

void
rc_you_file_slist_unref (RCYouFileSList *list)
{
    GSList *iter;

    for (iter = list; iter; iter = iter->next)
        rc_you_file_unref ((RCYouFile *) iter->data);
}
