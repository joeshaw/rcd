/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-fetch.h
 *
 * Copyright (C) 2002 Ximian, Inc.
 *
 * Developed by Jon Trowbridge <trow@ximian.com>
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

#ifndef __RCD_FETCH_H__
#define __RCD_FETCH_H__

#include <libredcarpet.h>

/* 
   Download the channel list from the server, then
   add the channels corresponding to our disto to the global
   RCWorld. 
*/
void rcd_fetch_channel_list (void);

/* 
   Download a channel's package data from the server,
   storing the packages in our RCWorld.  Returns the id
   of the RCDPending.
*/
gint rcd_fetch_channel (RCChannel *channel);

/*
  Download channel package data for all channels.
*/
void rcd_fetch_all_channels (void);

#endif /* __RCD_FETCH_H__ */

