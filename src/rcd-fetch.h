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

#include "rcd-transfer-pool.h"

/*
 * Functions marked "local" try to read the data from a last known good
 * file and return FALSE if unable to load from it.
 */

/*
 * Registers the daemon with the server.  This is done automatically at
 * startup when in premium services mode and an org id is set, with a
 * NULL activation code and email.  This is the "new" automatic style.
 *
 * "Old", RCX-style activation with an activation code and email address
 * is also possible, by passing in non-NULL values for activation_code
 * and email.  If in premium services mode, this will connect to the
 * currently set host.  Otherwise, it will connect to the default
 * activation host.
 *
 * As of 1.4 a third field, "alias" was added.  It specifies an alias
 * for the machine when it can't be readily identified by hostname.
 *
 * Also as of 1.4 an error message is returned through the err_msg
 * parameter if appropriate.
 *
 * Returns TRUE on success.
 */
gboolean rcd_fetch_register (const char  *activation_code,
                             const char  *email,
                             const char  *alias,
                             char       **err_msg);

/*
 * Download the (un)supported/deprecated distro information from the server.
 * This -must- be done before the RCWorld is initialized.  If we don't find
 * it, we'll fall back to some built-in data.  Returns TRUE on success.
 */
gboolean rcd_fetch_distro (void);

/*
 * Download the list of licenses that we know about
 */

gboolean rcd_fetch_licenses       (void);
gboolean rcd_fetch_licenses_local (void);

/* 
   Download the channel list from the server, then
   add the channels corresponding to our disto to the global
   RCWorld.  Returns TRUE if successful.
*/
gboolean rcd_fetch_channel_list       (RCWorld *world, char **err_msg);
gboolean rcd_fetch_channel_list_local (RCWorld *world);

/* 
   Download a channel's package data from the server,
   storing the packages in our RCWorld.  Returns the id
   of the RCDPending.
*/
gint     rcd_fetch_channel       (RCChannel *channel, RCWorld *world);
gboolean rcd_fetch_channel_local (RCChannel *channel, RCWorld *world);

/*
  Download channel package data for all channels.
  Returns a list of the ids of the RCPendings; the caller
  is responsible for freeing the list.
*/

typedef enum {
    RCD_FETCH_LOCAL      = 1<<0,
    RCD_FETCH_TRANSIENT  = 1<<1,
    RCD_FETCH_PERSISTENT = 1<<2,
} RCDFetchChannelFlags;

GSList *rcd_fetch_all_channels       (RCWorld *world);
void    rcd_fetch_all_channels_local (RCWorld *world);
GSList *rcd_fetch_some_channels      (RCDFetchChannelFlags flags,
                                      RCWorld *world);

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
  Download mirrors
*/
void     rcd_fetch_mirrors       (void);
gboolean rcd_fetch_mirrors_local (void);

/*
 * Refresh channel data, news and mirrors.  Returns a list of pending
 * IDs for the channel data.  The optional out parameter is an error
 * message in case it fails.
 */
GSList *rcd_fetch_refresh (char **err_msg);

/*
 * Set up an RCDTransferPool to download all of the packages specified.
 */
RCDTransferPool *rcd_fetch_packages (RCPackageSList *packages);

#endif /* __RCD_FETCH_H__ */

