/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-rpc.c
 *
 * Copyright (C) 2002 Ximian, Inc.
 *
 */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License, version 2,
 * as published by the Free Software Foundation.
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

#include <time.h>

#include <xmlrpc.h>

#include "rcd-module.h"
#include "rcd-rpc.h"
#include "rcd-rpc-system.h"

static xmlrpc_value *
system_ping(xmlrpc_env *env, xmlrpc_value *param_array, void *user_data)
{
    xmlrpc_value *result;

    result = xmlrpc_build_value(env, "i", time(NULL));
    if (env->fault_occurred)
        return NULL;

    return result;
} /* system_ping */

static xmlrpc_value *
system_query_module(xmlrpc_env   *env,
                    xmlrpc_value *param_array,
                    void         *user_data)
{
    char *module_name;
    gboolean module_present;
    xmlrpc_value *result;

    xmlrpc_parse_value(env, param_array, "(s)", &module_name);
    if (env->fault_occurred)
        return NULL;

    module_present = rcd_module_query(module_name);

    result = xmlrpc_build_value(env, "b", module_present);
    if (env->fault_occurred)
        return NULL;

    return result;
} /* system_query_module */
	
void
rcd_rpc_system_register_methods(void)
{
    rcd_rpc_register_method(
        "rcd.system.ping", system_ping, RCD_AUTH_NONE, NULL);
	rcd_rpc_register_method(
        "rcd.system.query_module", system_query_module, RCD_AUTH_NONE, NULL);
} /* rcd_rpc_system_register_methods */

