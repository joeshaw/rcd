/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-world-remote.h
 *
 * Copyright (C) 2003 Ximian, Inc.
 *
 */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
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

#ifndef __RCD_WORLD_REMOTE_H__
#define __RCD_WORLD_REMOTE_H__

#include <libredcarpet.h>

#include "rcd-mirror.h"
#include "rcd-news.h"

#define RCD_TYPE_WORLD_REMOTE            (rcd_world_remote_get_type ())
#define RCD_WORLD_REMOTE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), \
                                         RCD_TYPE_WORLD_REMOTE, \
                                         RCDWorldRemote))
#define RCD_WORLD_REMOTE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), \
                                         RCD_TYPE_WORLD_REMOTE, \
                                         RCDWorldRemoteClass))
#define RCD_IS_WORLD_REMOTE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), \
                                         RCD_TYPE_WORLD_REMOTE))
#define RCD_IS_WORLD_REMOTE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), \
                                         RCD_TYPE_WORLD_REMOTE))
#define RCD_WORLD_REMOTE_GET_CLASS(obj)  (RCD_WORLD_REMOTE_CLASS (G_OBJECT_GET_CLASS (obj)))

typedef struct _RCDWorldRemote RCDWorldRemote;
typedef struct _RCDWorldRemoteClass RCDWorldRemoteClass;

struct _RCDWorldRemote {
    RCWorldService parent;

    char *contact_email;
    gboolean premium_service;

    char *distributions_file;
    char *mirrors_file;
    char *licenses_file;
    char *news_file;

    RCDistro *distro;
    GSList *mirrors;
    GHashTable *licenses;
    GSList *news_items;
};

struct _RCDWorldRemoteClass {
    RCWorldServiceClass parent_class;
};

GType rcd_world_remote_get_type (void);

RCWorld *rcd_world_remote_new (const char *url);

void rcd_world_remote_register_service (void);

/*** Licenses ***/

void rcd_world_remote_add_license (RCDWorldRemote *remote,
                                   const char     *name,
                                   char           *license_text);

void rcd_world_remote_remote_license (RCDWorldRemote *remote,
                                      const char     *name);

void rcd_world_remote_clear_licenses (RCDWorldRemote *remote);

const char *rcd_world_remote_lookup_license (RCDWorldRemote *remote,
                                             const char     *name);

/*** Mirrors ***/

typedef void (RCDWorldRemoteForeachMirrorFn) (RCDMirror *mirror,
                                              gpointer   user_data);

void rcd_world_remote_add_mirror (RCDWorldRemote *remote,
                                  RCDMirror      *mirror);

void rcd_world_remote_clear_mirrors (RCDWorldRemote *remote);

void rcd_world_remote_foreach_mirror (RCDWorldRemote                 *remote,
                                      RCDWorldRemoteForeachMirrorFn  fn,
                                      gpointer                       user_data);

/*** News ***/

typedef void (RCDWorldRemoteForeachNewsFn) (RCDNews *news,
                                            gpointer user_data);

void rcd_world_remote_add_news (RCDWorldRemote *remote,
                                RCDNews        *news);

void rcd_world_remote_clear_news (RCDWorldRemote *remote);

void rcd_world_remote_foreach_news (RCDWorldRemote              *remote,
                                    RCDWorldRemoteForeachNewsFn  fn,
                                    gpointer                     user_data);

#endif /* __RCD_WORLD_REMOTE_H__ */

