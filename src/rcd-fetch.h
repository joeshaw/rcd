/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-fetch.h
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

#ifndef __RCD_FETCH_H__
#define __RCD_FETCH_H__

#include <libredcarpet.h>

/*
 * Functions marked "local" try to read the data from a last known good
 * file and return FALSE if unable to load from it.
 */

/* Register the daemon against the server, if we're in premium mode */
void     rcd_fetch_register (void);

/*
 * Download the (un)supported/deprecated distro information from the server.
 * This -must- be done before the RCWorld is initialized.  If we don't find
 * it, we'll fall back to some built-in data.  Returns whether it succeded.
 */
gboolean rcd_fetch_distro (void);

/* 
   Download the channel list from the server, then
   add the channels corresponding to our disto to the global
   RCWorld.  Returns TRUE if successful.
*/
gboolean rcd_fetch_channel_list       (void);
gboolean rcd_fetch_channel_list_local (void);

/* 
   Download a channel's package data from the server,
   storing the packages in our RCWorld.  Returns the id
   of the RCDPending.
*/
gint     rcd_fetch_channel       (RCChannel *channel);
gboolean rcd_fetch_channel_local (RCChannel *channel);

/*
  Download channel package data for all channels.
  Returns a list of the ids of the RCPendings; the caller
  is responsible for freeing the list.
*/
GSList *rcd_fetch_all_channels       (void);
void    rcd_fetch_all_channels_local (void);

/*
 * Download channel icons.  If they're already on the system, they won't
 * be downloaded again unless the refetch argument is set
 */
int  rcd_fetch_channel_icon      (RCChannel *channel);
void rcd_fetch_all_channel_icons (gboolean refretch);

/*
  Download news
*/
void     rcd_fetch_news       (void);
gboolean rcd_fetch_news_local (void);

/*
 * Download a list of packages and call the specified callback when they
 * all finish.
 */
typedef void (*RCDFetchProgressFunc)  (gsize size, gpointer user_data);
typedef void (*RCDFetchCompletedFunc) (gboolean    successful,
                                       const char *error_string,
                                       gpointer    user_data);

void rcd_fetch_packages (RCPackageSList        *packages,
                         int                    pending_id,
                         RCDFetchProgressFunc   progress_callback,
                         RCDFetchCompletedFunc  completed_callback,
                         gpointer               user_data);

void rcd_fetch_packages_abort (int pending_id);


#endif /* __RCD_FETCH_H__ */

