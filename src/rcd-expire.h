/* This is -*- C -*- */
/* vim: set sw=2: */
/* $Id$ */

/*
 * rcd-expire.h
 *
 * Copyright (C) 2002 The Free Software Foundation, Inc.
 *
 * Developed by Jon Trowbridge <trow@gnu.org>
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

#ifndef __RCD_EXPIRE_H__
#define __RCD_EXPIRE_H__

#include <glib.h>

void rcd_expire_by_age (const char *base_path,
			const char *glob,
			gboolean    recursive,
			double      max_age_in_days);

void rcd_expire_by_size (const char *base_path,
			 const char *glob,
			 gboolean    recursive,
			 double      max_size_in_mb,
			 double      min_age_in_days);
			 

#endif /* __RCD_EXPIRE_H__ */

