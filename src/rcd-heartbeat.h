/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-heartbeat.h
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

#ifndef __RCD_HEARTBEAT_H__
#define __RCD_HEARTBEAT_H__

#include <glib.h>

typedef void (*RCDHeartbeatFunc) (gpointer user_data);

void rcd_heartbeat_start (void);
void rcd_heartbeat_stop  (void);

void rcd_heartbeat_register_func (RCDHeartbeatFunc func, gpointer user_data);

#endif /* __RCD_HEARTBEAT_H__ */
