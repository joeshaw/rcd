/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-mirror.h
 *
 * Copyright (C) 2003 Ximian, Inc.
 *
 */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 * License, or (at your option) any later version.
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

#ifndef __RCD_MIRRORS_H__
#define __RCD_MIRRORS_H__

#include <glib.h>
#include <libxml/tree.h>

typedef struct _RCDMirror RCDMirror;

typedef void (*RCDMirrorFn) (RCDMirror *, gpointer user_data);

struct _RCDMirror {
    char *name;
    char *location;
    char *url;
    char *ftp;
    char *contact;
};

RCDMirror *rcd_mirror_parse   (xmlNode *item_node);
void       rcd_mirror_free    (RCDMirror *);

void       rcd_mirror_add     (RCDMirror *);
void       rcd_mirror_clear   (void);

void       rcd_mirror_foreach (RCDMirrorFn fn, gpointer user_data);


#endif /* __RCD_MIRRORS_H__ */

