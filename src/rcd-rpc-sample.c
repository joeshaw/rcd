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

#include <xmlrpc.h>

#include "rcd-module.h"
#include "rcd-rpc.h"
#include "rcd-rpc-sample.h"

static xmlrpc_value *
sample_add(xmlrpc_env *env, xmlrpc_value *param_array, void *user_data)
{
    xmlrpc_int32 x, y, z;

    xmlrpc_parse_value(env, param_array, "(ii)", &x, &y);
    if (env->fault_occurred)
        g_error("fuck");

    z = x + y;

    return xmlrpc_build_value(env, "i", z);
} /* sample_add */
	
void
rcd_module_load(RCDModule *module)
{
    /* Initialize the module */
    module->name = "rcd.sample";
    module->description = "A Sample Module";

    /* Register RPC methods */
    rcd_rpc_register_method ("rcd.sample.add", sample_add, NULL, NULL);
} /* rcd_module_load */

