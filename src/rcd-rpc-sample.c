/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

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
    rcd_rpc_register_method("rcd.sample.add", sample_add, RCD_AUTH_NONE, NULL);
} /* rcd_module_load */

