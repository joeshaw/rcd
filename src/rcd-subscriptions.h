/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * rcd-subscriptions.h: Code for managing subscriptions
 *
 * Copyright (c) 2000-2002 Ximian, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef __RCD_SUBSCRIPTIONS_H
#define __RCD_SUBSCRIPTIONS_H

#include <libredcarpet.h>

void rcd_subscriptions_load (void);

void rcd_subscriptions_save (void);

#endif /* __RCD_SUBSCRIPTIONS_H */
