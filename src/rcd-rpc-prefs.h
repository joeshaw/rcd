/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-rpc-prefs.h
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

#ifndef __RCD_RPC_PREFS_H__
#define __RCD_RPC_PREFS_H__

#include <glib.h>

typedef gpointer      (*RCDPrefGetFunc) (void);
typedef gboolean      (*RCDPrefSetFunc) (gpointer);

typedef enum _RCDPrefType RCDPrefType;

enum _RCDPrefType {
    RCD_PREF_STRING = 0,
    RCD_PREF_BOOLEAN,
    RCD_PREF_INT
};

void rcd_rpc_prefs_register_pref (const char     *pref_name,
                                  RCDPrefType     pref_type,
                                  const char     *description,
                                  const char     *category,
                                  RCDPrefGetFunc  get_pref_func,
                                  const char     *get_privileges_str,
                                  RCDPrefSetFunc  set_pref_func,
                                  const char     *set_privileges_str);

void rcd_rpc_prefs_register_methods(void);

#endif /* __RCD_RPC_PREFS_H__ */
