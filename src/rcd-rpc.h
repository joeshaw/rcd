/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

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

#ifndef __RCD_RPC_H__
#define __RCD_RPC_H__

#include <glib.h>
#include <xmlrpc.h>

#include "rcd-auth.h"

typedef struct {
    char *host;

    RCDIdentity *identity;
} RCDRPCMethodData;

RCDRPCMethodData *rcd_rpc_get_method_data (void);

int rcd_rpc_register_method (const char        *method_name,
                             xmlrpc_method      method,
                             RCDAuthActionList *required_privileges,
                             gpointer           user_data);

void rcd_rpc_server_start (void);
void rcd_rpc_init (void);

#endif /* __RCD_RPC_H__ */
