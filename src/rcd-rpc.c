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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <libsoup/soup-server.h>
#include <libsoup/soup-socket.h>

#include <libredcarpet.h>

#include "rcd-auth.h"
#include "rcd-identity.h"
#include "rcd-rpc.h"
#include "rcd-rpc-system.h"
#include "rcd-unix-server.h"

typedef struct {
    const char    *method_name;
    xmlrpc_method  method;
    RCDAuthAction  req_privs;
} RCDRPCMethodInfo;

static xmlrpc_registry *registry = NULL;
GHashTable *method_info_hash = NULL;

static GByteArray *
unix_rpc_callback (GByteArray *in_data)
{
    xmlrpc_env env;
    xmlrpc_mem_block *output;
    GByteArray *out_data;

    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Handling RPC connection");

    xmlrpc_env_init(&env);

    output = xmlrpc_registry_process_call(
        &env, registry, NULL, in_data->data, in_data->len);

    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Call processed");

    if (env.fault_occurred) {
        g_warning ("Some weird fault during registry processing");
        return NULL;
    }

    out_data = g_byte_array_new();
    g_byte_array_append(out_data, 
                        XMLRPC_TYPED_MEM_BLOCK_CONTENTS(char, output),
                        XMLRPC_TYPED_MEM_BLOCK_SIZE(char, output));

    xmlrpc_mem_block_free(output);

    return out_data;
} /* unix_rpc_callback */    

static xmlrpc_mem_block *
serialize_permission_fault (void)
{
    xmlrpc_env tmp_env;
    xmlrpc_env fault;
    xmlrpc_mem_block *output;

    xmlrpc_env_init (&tmp_env);
    xmlrpc_env_init (&fault);

    output = xmlrpc_mem_block_new (&tmp_env, 0);
    XMLRPC_FAIL_IF_FAULT (&tmp_env);

    xmlrpc_env_set_fault (&fault, -610, "Permission denied");

    xmlrpc_serialize_fault (&tmp_env, output, &fault);
    XMLRPC_FAIL_IF_FAULT (&tmp_env);

    return output;

cleanup:
    return NULL;
} /* serialize_permission_fault */



static void
soup_rpc_callback (SoupServerContext *context, SoupMessage *msg, gpointer data)
{
    const char *username;
    RCDIdentity *identity;
    xmlrpc_env env;
    char *method_name;
    xmlrpc_value *param_array;
    RCDRPCMethodInfo *method_info;
    xmlrpc_mem_block *output;

    xmlrpc_env_init (&env);

    /* Authenticate the user's password */
    if (getenv ("RCD_ENFORCE_AUTH")) {
        username = soup_server_auth_get_user (context->auth);
        identity = rcd_identity_from_password_file (username);

        if (!soup_server_auth_check_passwd (context->auth,
                                            identity->password)) {
            g_print ("[%d]: Couldn't authenticate %s\n",
                     getpid(), identity->username);
            
            rcd_identity_free (identity);
            output = serialize_permission_fault ();

            goto finish_request;
        }
    }

    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Handling RPC connection");

    if (getenv ("RCD_ENFORCE_AUTH")) {
        /* Kind of lame just to get the method name */
        xmlrpc_parse_call (&env, msg->request.body, msg->request.length,
                           &method_name, &param_array);
        xmlrpc_DECREF (param_array);

        method_info = g_hash_table_lookup (method_info_hash, method_name);

        if (!rcd_auth_approve_action (identity,
                                      method_info->req_privs,
                                      NULL)) {
            output = serialize_permission_fault ();

            goto finish_request;
        }
    }
        
    output = xmlrpc_registry_process_call(
        &env, registry, NULL, msg->request.body, msg->request.length);

    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Call processed");

    if (env.fault_occurred) {
        soup_message_set_error(msg, SOUP_ERROR_BAD_REQUEST);
        return;
    }

finish_request:
    /* Let Soup free the data for us */
    msg->response.owner = SOUP_BUFFER_SYSTEM_OWNED;
    msg->response.length = XMLRPC_TYPED_MEM_BLOCK_SIZE(char, output);
    msg->response.body = g_memdup(
        XMLRPC_TYPED_MEM_BLOCK_CONTENTS(char, output), msg->response.length);

    soup_message_set_error(msg, SOUP_ERROR_OK);

    xmlrpc_mem_block_free(output);
} /* soup_rpc_callback */

static void
soup_default_callback(SoupServerContext *context, SoupMessage *msg, gpointer data)
{
    soup_message_set_error(msg, SOUP_ERROR_NOT_FOUND);
} /* default_callback */

static gboolean
soup_auth_callback (SoupServerAuthContext *auth_ctx,
                    SoupServerAuth        *auth,
                    SoupMessage           *msg,
                    gpointer               user_data)
{
    if (!auth) {
        if (getenv("RCD_ENFORCE_AUTH"))
            return FALSE;
        else
            return TRUE;
    }

    return TRUE;
} /* auth_callback */

static gpointer
run_server_thread(gpointer user_data)
{
    SoupServer *server;
    SoupServerAuthContext auth_ctx = { 0 };

    rc_debug (RC_DEBUG_LEVEL_ALWAYS, "Starting server");

    server = soup_server_new(SOUP_PROTOCOL_HTTP, 5505);

    if (!server)
        g_error("Could not start RPC server");

    auth_ctx.types = SOUP_AUTH_TYPE_BASIC;
    auth_ctx.callback = soup_auth_callback;
    auth_ctx.basic_info.realm = "RCD";

    soup_server_register(
        server, "/RPC2", &auth_ctx, soup_rpc_callback, NULL, NULL);
    soup_server_register(
        server, NULL, NULL, soup_default_callback, NULL, NULL);

    soup_server_run_async(server);

    rcd_unix_server_run_async(unix_rpc_callback);

    return NULL;
} /* run_server_thread */

int
rcd_rpc_register_method(const char *method_name, xmlrpc_method method,
                        RCDAuthAction required_privs, gpointer user_data)
{
    xmlrpc_env env;
    RCDRPCMethodInfo *info;

    if (!registry)
        rcd_rpc_init ();

    rc_debug (RC_DEBUG_LEVEL_INFO,
              "Registering method %s", method_name);

    xmlrpc_env_init(&env);
    xmlrpc_registry_add_method(
        &env, registry, NULL, (char *) method_name, method, user_data);

    if (env.fault_occurred) {
        g_warning("Unable to add \"%s\" method: %s (%d)",
                  method_name, env.fault_string, env.fault_code);
        return -1;
    }

    xmlrpc_env_clean(&env);

    info = g_new0 (RCDRPCMethodInfo, 1);
    info->method_name = method_name;
    info->method = method;
    info->req_privs = required_privs;

    g_hash_table_insert (method_info_hash, (char *) method_name, info);

    return 0;
} /* rcd_rpc_register_method */

void
rcd_rpc_init(void)
{
    xmlrpc_env env;
    GThread *thread;

    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Initializing RPC system");

    if (!g_thread_supported())
        g_thread_init(NULL);

    xmlrpc_env_init(&env);
    registry = xmlrpc_registry_new(&env);

    if (env.fault_occurred) {
        g_error("Unable to initialize the XML-RPC server "
                "registry: %s (%d)", env.fault_string, env.fault_code);
    }

    xmlrpc_env_clean(&env);

    method_info_hash = g_hash_table_new (g_str_hash, g_str_equal);

    /* Register the basic RPC calls (ping, querying for modules, etc.) */
    rcd_rpc_system_register_methods();

    /* FIXME: Probably use g_thread_create() here */
    g_idle_add(run_server_thread, NULL);
} /* rcd_rpc_init */
