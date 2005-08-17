/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rc-you-file.h
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

#ifndef __RC_YOU_FILE__
#define __RC_YOU_FILE__

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _RCYouFile RCYouFile;
typedef GSList RCYouFileSList;

struct _RCYouFile {
    gchar *filename;
    gchar *url;
    gchar *local_path;
    guint32 size;

    gint refs;
};

RCYouFile      *rc_you_file_new            (const gchar *filename);
void            rc_you_file_set_url        (RCYouFile *file, gchar *url);
void            rc_you_file_set_local_path (RCYouFile *file, gchar *path);
void            rc_you_file_free           (RCYouFile *file);
RCYouFile      *rc_you_file_ref            (RCYouFile *file);
void            rc_you_file_unref          (RCYouFile *file);
RCYouFileSList *rc_you_file_slist_ref      (RCYouFileSList *list);
void            rc_you_file_slist_unref    (RCYouFileSList *list);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /*__RC_YOU_FILE__ */
