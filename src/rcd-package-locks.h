/* This is -*- C -*- */
/* vim: set sw=2: */
/* $Id$ */

/*
 * rcd-package-locks.h
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

#ifndef __RCD_PACKAGE_LOCKS_H__
#define __RCD_PACKAGE_LOCKS_H__

#include <libredcarpet.h>

void  rcd_package_locks_load (RCWorld *world);
void  rcd_package_locks_save (RCWorld *world);

#endif /* __RCD_PACKAGE_LOCKS_H__ */

