/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-shutdown.h
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

#ifndef __RCD_SHUTDOWN_H__
#define __RCD_SHUTDOWN_H__

#include <glib.h>

typedef void (*RCDShutdownFn) (gpointer);

/* At shutdown time, handlers are executed in the
   reverse of the order in which they are added. */
void rcd_shutdown_add_handler (RCDShutdownFn fn,
                               gpointer      user_data);

void rcd_shutdown_block (void);

void rcd_shutdown_allow (void);

/* rcd_shutdown does return.  The actual shutdown happens
   in an idle function. */

void rcd_shutdown (void);

#endif /* __RCD_SHUTDOWN_H__ */

