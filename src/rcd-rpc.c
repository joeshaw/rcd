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

#include <config.h>
#include "rcd-rpc.h"

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <libsoup/soup-server.h>
#include <libsoup/soup-socket.h>

#include <libredcarpet.h>

#include "rcd-identity.h"
#include "rcd-prefs.h"
#include "rcd-privileges.h"
#include "rcd-rpc-system.h"
#include "rcd-rpc-util.h"
#include "rcd-shutdown.h"
#include "rcd-unix-server.h"

typedef struct {
    const char        *method_name;
    xmlrpc_method      method;
    RCDPrivileges      req_privs;
} RCDRPCMethodInfo;

static xmlrpc_registry *registry = NULL;
static GHashTable *method_info_hash = NULL;
static RCDRPCMethodData *current_method_data = NULL;

static xmlrpc_mem_block *
serialize_fault (int fault_code, const char *fault_string)
{
    xmlrpc_env tmp_env;
    xmlrpc_env fault;
    xmlrpc_mem_block *output;

    xmlrpc_env_init (&tmp_env);
    xmlrpc_env_init (&fault);

    output = xmlrpc_mem_block_new (&tmp_env, 0);
    XMLRPC_FAIL_IF_FAULT (&tmp_env);

    xmlrpc_env_set_fault (&fault, fault_code, (char *) fault_string);

    xmlrpc_serialize_fault (&tmp_env, output, &fault);
    XMLRPC_FAIL_IF_FAULT (&tmp_env);

    return output;

cleanup:
    return NULL;
} /* serialize_fault */

static void
access_control_check (xmlrpc_env   *env,
                      char         *method_name,
                      xmlrpc_value *param_array,
                      void         *user_data)
{
    RCDIdentity *identity = (RCDIdentity *) user_data;
    RCDRPCMethodInfo *method_info;
    char *str;

    g_assert (identity != NULL);

    method_info = g_hash_table_lookup (method_info_hash, method_name);

    rc_debug (RC_DEBUG_LEVEL_INFO, 
              "Method being called: %s", method_name);

    if (method_info) {
        str = rcd_privileges_to_string (method_info->req_privs);
        rc_debug (RC_DEBUG_LEVEL_INFO,
                  "Requires Privileges: %s", str);
        g_free (str);
              
    }

    str = rcd_privileges_to_string (identity->privileges);
    rc_debug (RC_DEBUG_LEVEL_INFO,
              "    User Privileges: %s", str);
    g_free (str);

    if (method_info
        && ! rcd_identity_approve_action (identity, method_info->req_privs)) {
        
        xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PERMISSION_DENIED, 
                              "Permission denied");
            
        rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Unable to approve action");
    }
} /* access_control_check */

static xmlrpc_mem_block *
process_rpc_call (xmlrpc_env       *env,
                  const char       *data,
                  gsize             size,
                  RCDRPCMethodData *method_data)
{
    xmlrpc_mem_block *output;

    rc_debug (RC_DEBUG_LEVEL_INFO, "Handling RPC connection");

    if (current_method_data)
        rc_debug (RC_DEBUG_LEVEL_CRITICAL, 
                  "### REENTRANCY in an RPC call");
    current_method_data = method_data;

    /* Set up the access control check function */
    xmlrpc_registry_set_preinvoke_method (
        env, registry, access_control_check, method_data->identity);

    output = xmlrpc_registry_process_call (
        env, registry, NULL, (char *) data, size);
    
    current_method_data = NULL;

    rc_debug (RC_DEBUG_LEVEL_INFO, "Call processed");

    return output;
} /* process_rpc_call */
    
static GByteArray *
unix_rpc_callback (RCDUnixServerHandle *handle)
{
    xmlrpc_env env;
    xmlrpc_mem_block *output;
    GByteArray *out_data;
    RCDIdentity *identity = NULL;
    RCDRPCMethodData *method_data;

    xmlrpc_env_init(&env);

    if (handle->uid != 0) {
        struct passwd *pw;
        
        pw = getpwuid (handle->uid);
        if (!pw) {
            rc_debug (RC_DEBUG_LEVEL_WARNING,
                      "Couldn't get info for UID %d\n", handle->uid);
            identity = NULL;
        }
        else {
            if (rcd_identity_password_file_is_secure ())
                identity = rcd_identity_from_password_file (pw->pw_name);

            if (!identity) {
                identity = rcd_identity_new ();
                identity->username = g_strdup (pw->pw_name);
                identity->privileges = rcd_privileges_from_string ("view");
            }
        }
    }
    else {
        identity = rcd_identity_new ();
        identity->username = g_strdup ("root");
        identity->privileges = rcd_privileges_from_string ("superuser");
    }
    
    if (!identity) {
        output = serialize_fault (RCD_RPC_FAULT_PERMISSION_DENIED,
                                  "Permission denied");
        goto finish_request;
    }

    method_data = g_new0 (RCDRPCMethodData, 1);
    method_data->host = "local";
    method_data->identity = identity;

    output = process_rpc_call (
        &env, handle->data->data, handle->data->len, method_data);

    rcd_identity_free (method_data->identity);
    g_free (method_data);

    if (env.fault_occurred) {
        rc_debug (RC_DEBUG_LEVEL_ERROR, "Some weird fault during registry processing");
        return NULL;
    }

finish_request:
    out_data = g_byte_array_new ();
    out_data = g_byte_array_append (
        out_data, 
        XMLRPC_TYPED_MEM_BLOCK_CONTENTS(char, output),
        XMLRPC_TYPED_MEM_BLOCK_SIZE(char, output));

    xmlrpc_mem_block_free(output);

    return out_data;
} /* unix_rpc_callback */    

static void
soup_rpc_callback (SoupServerContext *context, SoupMessage *msg, gpointer data)
{
    xmlrpc_env env;
    xmlrpc_mem_block *output;
    const char *username;
    RCDIdentity *identity;
    RCDRPCMethodData *method_data;

    xmlrpc_env_init (&env);

    method_data = g_new0 (RCDRPCMethodData, 1);

    /* Authenticate the user's password */
    username = soup_server_auth_get_user (context->auth);
    identity = rcd_identity_from_password_file (username);

    if (! rcd_identity_password_file_is_secure ()
        || !identity
        || !soup_server_auth_check_passwd (context->auth,
                                           identity->password)) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Couldn't authenticate %s", username);
        
        rcd_identity_free (identity);
        output = serialize_fault (RCD_RPC_FAULT_CANT_AUTHENTICATE,
                                  "Couldn't authenticate user");
        
        goto finish_request;
    }

    method_data->host = soup_server_context_get_client_host (context);
    method_data->identity = identity;

    output = process_rpc_call (
        &env, msg->request.body, msg->request.length, method_data);

    rcd_identity_free (method_data->identity);
    g_free (method_data->host);
    g_free (method_data);

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
    /* 
     * If there wasn't any authentication data passed back, we have to fail
     * the call.
     */
    if (!auth)
        return FALSE;
    else
        return TRUE;
} /* auth_callback */

static void
soup_shutdown_cb (gpointer user_data)
{
    SoupServer *server = user_data;

    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Shutting down HTTP server");

    soup_server_unref (server);
} /* soup_shutdown_cb */

RCDRPCMethodData *
rcd_rpc_get_method_data (void)
{
    return current_method_data;
} /* rcd_rpc_get_method_data */

int
rcd_rpc_register_method(const char   *method_name,
                        xmlrpc_method method,
                        const char   *privilege_str,
                        gpointer      user_data)
{
    xmlrpc_env env;
    RCDPrivileges priv;
    RCDRPCMethodInfo *info;

    if (!registry)
        rcd_rpc_init ();

    rc_debug (RC_DEBUG_LEVEL_DEBUG,
              "Registering method %s", method_name);

    if (privilege_str == NULL)
        privilege_str = "";

    priv = rcd_privileges_from_string (privilege_str);
    
    xmlrpc_env_init(&env);
    xmlrpc_registry_add_method(
        &env, registry, NULL, (char *) method_name, method, user_data);

    if (env.fault_occurred) {
        rc_debug (RC_DEBUG_LEVEL_ERROR,
                  "Unable to add \"%s\" method: %s (%d)",
                  method_name, env.fault_string, env.fault_code);
        return -1;
    }

    xmlrpc_env_clean(&env);

    info = g_new0 (RCDRPCMethodInfo, 1);
    info->method_name = method_name;
    info->method = method;
    info->req_privs = priv;

    g_hash_table_insert (method_info_hash, (char *) method_name, info);

    return 0;
} /* rcd_rpc_register_method */

void
rcd_rpc_server_start (int port)
{
    SoupServer *server;
    SoupServerAuthContext auth_ctx = { 0 };

    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Starting server");

    /* 
     * port of -1 means disable the remote server
     * port of 0 means use the default port from the config
     */

    if (port != -1 && rcd_prefs_get_remote_server_enabled ()) {
        if (!port)
            port = rcd_prefs_get_remote_server_port ();

        soup_set_ssl_cert_files(SHAREDIR "/rcd.pem",
                                SHAREDIR "/rcd.pem");

        server = soup_server_new(SOUP_PROTOCOL_HTTPS, port);

        if (!server) {
            rc_debug (RC_DEBUG_LEVEL_ERROR, "Could not start RPC server on port %d", port);
            rc_debug (RC_DEBUG_LEVEL_ERROR, "(This probably means that you're running not as root and not using");
            rc_debug (RC_DEBUG_LEVEL_ERROR, "a non-privileged port, or another rcd process is already running.)");
            exit (-1);
        }

        auth_ctx.types = SOUP_AUTH_TYPE_DIGEST;
        auth_ctx.callback = soup_auth_callback;
        auth_ctx.digest_info.realm = "RCD";
        auth_ctx.digest_info.allow_algorithms = SOUP_ALGORITHM_MD5;
        auth_ctx.digest_info.force_integrity = FALSE;
        
        soup_server_register(
            server, "/RPC2", &auth_ctx, soup_rpc_callback, NULL, NULL);
        soup_server_register(
            server, NULL, NULL, soup_default_callback, NULL, NULL);
        
        rcd_shutdown_add_handler (soup_shutdown_cb, server);
        
        soup_server_run_async(server);
    }

    if (rcd_unix_server_run_async(unix_rpc_callback)) {
        rc_debug (RC_DEBUG_LEVEL_ERROR, "Unable to listen for local connections.");
        exit (-1);
    }
} /* rcd_rpc_server_start */

void
rcd_rpc_init(void)
{
    xmlrpc_env env;

    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Initializing RPC system");

#if 0
    if (!g_thread_supported())
        g_thread_init(NULL);
#endif

    xmlrpc_env_init(&env);
    registry = xmlrpc_registry_new(&env);

    if (env.fault_occurred) {
        rc_debug (RC_DEBUG_LEVEL_ERROR, 
                  "Unable to initialize the XML-RPC server registry: %s (%d)",
                  env.fault_string, env.fault_code);
        exit (-1);
    }

    /* Create a hash which will be used for registering RPC methods */
    method_info_hash = g_hash_table_new (g_str_hash, g_str_equal);

    /* Register the basic RPC calls (ping, querying for modules, etc.) */
    rcd_rpc_system_register_methods();
} /* rcd_rpc_init */
