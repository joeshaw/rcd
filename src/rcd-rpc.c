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
#include <sys/types.h>
#include <unistd.h>

#include <libsoup/soup-server.h>
#include <libsoup/soup-socket.h>

#include "rcd-rpc.h"
#include "rcd-rpc-system.h"
#include "rcd-unix-server.h"

static xmlrpc_registry *registry = NULL;

static GByteArray *
unix_rpc_callback (GByteArray *in_data)
{
    xmlrpc_env env;
    xmlrpc_mem_block *output;
    GByteArray *out_data;

    g_print ("[%d]: Handling RPC connection\n", getpid());

    xmlrpc_env_init(&env);

    output = xmlrpc_registry_process_call(
        &env, registry, NULL, in_data->data, in_data->len);

    g_print ("[%d]: Call processed\n", getpid());

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

static void
soup_rpc_callback (SoupServerContext *context, SoupMessage *msg, gpointer data)
{
    xmlrpc_env env;
    xmlrpc_mem_block *output;

    g_print ("[%d]: Handling RPC connection\n", getpid());

    xmlrpc_env_init(&env);

    output = xmlrpc_registry_process_call(
        &env, registry, NULL, msg->request.body, msg->request.length);

    g_print ("[%d]: Call processed\n", getpid());

    if (env.fault_occurred) {
        soup_message_set_error(msg, SOUP_ERROR_BAD_REQUEST);
        return;
    }

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

static gpointer
run_server_thread(gpointer user_data)
{
    SoupServer *server;

    g_print ("[%d]: Starting server\n", getpid());

    server = soup_server_new(SOUP_PROTOCOL_HTTP, 5505);

    if (!server)
        g_error("Could not start RPC server");

    soup_server_register(server, "/RPC2", NULL, soup_rpc_callback, NULL, NULL);
    soup_server_register(
        server, NULL, NULL, soup_default_callback, NULL, NULL);

    soup_server_run_async(server);

    rcd_unix_server_run_async(unix_rpc_callback);

    return NULL;
} /* run_server_thread */

int
rcd_rpc_register_method(const char *method_name, xmlrpc_method method,
                        gpointer user_data)
{
	xmlrpc_env env;

	if (!registry)
		rcd_rpc_init ();

    g_print ("[%d]: Registering method %s\n", getpid(), method_name);

	xmlrpc_env_init(&env);
    xmlrpc_registry_add_method(
		&env, registry, NULL, (char *) method_name, method, user_data);

	if (env.fault_occurred) {
		g_warning("Unable to add \"%s\" method: %s (%d)",
			  method_name, env.fault_string, env.fault_code);
		return -1;
	}

	xmlrpc_env_clean(&env);

	return 0;
} /* rcd_rpc_register_method */

void
rcd_rpc_init(void)
{
	xmlrpc_env env;
    GThread *thread;

    g_print ("[%d]: Initializing RPC system\n", getpid());

    if (!g_thread_supported())
        g_thread_init(NULL);

	xmlrpc_env_init(&env);
	registry = xmlrpc_registry_new(&env);

	if (env.fault_occurred) {
		g_error("Unable to initialize the XML-RPC server "
			"registry: %s (%d)", env.fault_string, env.fault_code);
	}

	xmlrpc_env_clean(&env);

    /* Register the basic RPC calls (ping, querying for modules, etc.) */
    rcd_rpc_system_register_methods();

    /* FIXME: Probably use g_thread_create() here */
    g_idle_add(run_server_thread, NULL);
} /* rcd_rpc_init */
