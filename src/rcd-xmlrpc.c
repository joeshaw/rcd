/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-xmlrpc.c
 *
 * Copyright (C) 2001 by First Peer, Inc. All rights reserved.
 * Copyright (C) 2003 Ximian, Inc.
 *
 * Derived from xmlrpc-c-0.9.10/src/xmlrpc_client.c
 */

/* Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdlib.h>
#include <string.h>
#include <libsoup/soup.h>
#include <rc-md5.h>

#define  XMLRPC_WANT_INTERNAL_DECLARATIONS
#include "rcd-xmlrpc.h"
#include "rcd-prefs.h"
#include "rcd-world-remote.h"

/*=========================================================================
**  xmlrpc_server_info
**=========================================================================
*/

xmlrpc_server_info *
xmlrpc_server_info_new (xmlrpc_env *env,
				    const char *server_url)
{
    xmlrpc_server_info *server;

    g_return_val_if_fail (server_url != NULL, NULL);

    server = g_new0 (xmlrpc_server_info, 1);
    server->_server_url = g_strdup (server_url);

    return server;
}

void
xmlrpc_server_info_free (xmlrpc_server_info *server)
{
    g_return_if_fail (server != NULL);

    if (server->_server_url)
        g_free (server->_server_url);
    if (server->_username)
        g_free (server->_username);
    if (server->_password)
        g_free (server->_password);

    g_free (server);
}

void
xmlrpc_server_info_set_auth (xmlrpc_env *env,
                             xmlrpc_server_info *server,
                             const char *username,
                             const char *password)
{
    gchar *digest;

    g_return_if_fail (server != NULL);
    g_return_if_fail (username != NULL);
    g_return_if_fail (password != NULL);

    g_free (server->_username);
    server->_username = g_strdup (username);

    g_free (server->_password);

    digest = g_strdup_printf ("%s:Express:%s", username, password);
    server->_password = rc_md5_digest_from_string (digest);
    g_free (digest);
}

static xmlrpc_server_info *
xmlrpc_server_info_copy (xmlrpc_server_info *server)
{
    xmlrpc_server_info *new;

    g_return_val_if_fail (server != NULL, NULL);

    new = g_new0 (xmlrpc_server_info, 1);

    if (server->_server_url)
        new->_server_url = g_strdup (server->_server_url);

    if (server->_username)
        new->_username = g_strdup (server->_username);

    if (server->_password)
        new->_password = g_strdup (server->_password);

    return new;
}

/******************************************************************************/

static void do_soup_request (xmlrpc_env *env,
                             char *uri,
                             char *xml_data,
                             size_t xml_len,
                             char **response,
                             size_t *response_len);

xmlrpc_value *
xmlrpc_client_call (xmlrpc_env *env,
                    char *server_url,
                    char *method_name,
                    char *format,
                    ...)
{
    va_list args;
    xmlrpc_value *arg_array, *retval;

    XMLRPC_ASSERT_ENV_OK(env);
    XMLRPC_ASSERT_PTR_OK(format);

    /* Error-handling preconditions. */
    arg_array = retval = NULL;

    /* Build our argument array. */
    va_start(args, format);
    arg_array = xmlrpc_build_value_va(env, format, args);
    va_end(args);
    XMLRPC_FAIL_IF_FAULT(env);

    /* Perform the actual XML-RPC call. */
    retval = xmlrpc_client_call_params(env, server_url, method_name,
                                       arg_array);
    XMLRPC_FAIL_IF_FAULT(env);

 cleanup:
    if (arg_array)
        xmlrpc_DECREF(arg_array);

    if (env->fault_occurred) {
        if (retval)
            xmlrpc_DECREF(retval);
        return NULL;
    }

    return retval;
}

xmlrpc_value *
xmlrpc_client_call_server (xmlrpc_env *env,
                           xmlrpc_server_info *server,
                           char *method_name,
                           char *format,
                           ...)
{
    va_list args;
    xmlrpc_value *arg_array, *retval;

    XMLRPC_ASSERT_ENV_OK(env);
    XMLRPC_ASSERT_PTR_OK(format);

    /* Error-handling preconditions. */
    arg_array = retval = NULL;

    /* Build our argument array. */
    va_start(args, format);
    arg_array = xmlrpc_build_value_va(env, format, args);
    va_end(args);
    XMLRPC_FAIL_IF_FAULT(env);

    /* Perform the actual XML-RPC call. */
    retval = xmlrpc_client_call_server_params(env, server, method_name,
                                              arg_array);
    XMLRPC_FAIL_IF_FAULT(env);

cleanup:
    if (arg_array)
        xmlrpc_DECREF(arg_array);

    if (env->fault_occurred) {
        if (retval)
            xmlrpc_DECREF(retval);
        return NULL;
    }

    return retval;
}

xmlrpc_value *
xmlrpc_client_call_params (xmlrpc_env *env,
                           char *server_url,
                           char *method_name,
                           xmlrpc_value *param_array)
{
    xmlrpc_server_info *server;
    xmlrpc_value *retval;

    XMLRPC_ASSERT_ENV_OK(env);
    XMLRPC_ASSERT_PTR_OK(server_url);

    /* Error-handling preconditions. */
    server = NULL;
    retval = NULL;

    /* Build a server info object and make our call. */
    server = xmlrpc_server_info_new(env, server_url);
    XMLRPC_FAIL_IF_FAULT(env);
    retval = xmlrpc_client_call_server_params(env, server, method_name,
                                              param_array);
    XMLRPC_FAIL_IF_FAULT(env);

cleanup:
    if (server)
        xmlrpc_server_info_free(server);

    if (env->fault_occurred) {
        if (retval)
            xmlrpc_DECREF(retval);
        return NULL;
    }

    return retval;
}

/* Insert username and password to the beginning of params */
static xmlrpc_value *
mungle_params (xmlrpc_env *env,
			xmlrpc_server_info *server,
			xmlrpc_value *param_array)
{
	xmlrpc_value *val;
	int i;

	if (!server->_username) {
		xmlrpc_INCREF (param_array);
		return param_array;
	}

	val = xmlrpc_build_value (env, "(ss)",
                              server->_username,
                              server->_password);

	for (i = 0; i < xmlrpc_array_size (env, param_array); i++)
		xmlrpc_array_append_item (env, val,
                                  xmlrpc_array_get_item (env, param_array, i));

	return val;
}

xmlrpc_value *
xmlrpc_client_call_server_params (xmlrpc_env *env,
                                  xmlrpc_server_info *server,
                                  char *method_name,
                                  xmlrpc_value *param_array)
{
	xmlrpc_value *retval = NULL;
	xmlrpc_value *mungled_params = NULL;
	xmlrpc_mem_block *serialized_xml = NULL;
	char *response_xml = NULL;
	size_t response_len = 0;

	mungled_params = mungle_params (env, server, param_array);
	XMLRPC_FAIL_IF_FAULT(env);

	/* Build the xml block */
	serialized_xml = xmlrpc_mem_block_new(env, 0);
	XMLRPC_FAIL_IF_FAULT(env);

	xmlrpc_serialize_call(env, serialized_xml, method_name, mungled_params);
	XMLRPC_FAIL_IF_FAULT(env);

	/* Perform actual call */
	do_soup_request(env, server->_server_url,
                    xmlrpc_mem_block_contents(serialized_xml),
                    xmlrpc_mem_block_size(serialized_xml),
                    &response_xml,
                    &response_len);

	XMLRPC_FAIL_IF_FAULT(env);

	/* Get the response back */
	retval = xmlrpc_parse_response (env, response_xml, response_len);
	XMLRPC_FAIL_IF_FAULT(env);

cleanup:
	if (mungled_params)
		xmlrpc_DECREF (mungled_params);
	if (serialized_xml)
		xmlrpc_mem_block_free (serialized_xml);
	if (response_xml)
		g_free (response_xml);

	if (env->fault_occurred) {
		return NULL;
	}
	return retval;
}

static void
do_soup_request (xmlrpc_env *env,
                 char *uri,
                 char *xml_data,
                 size_t xml_len,
                 char **response,
                 size_t *response_len)
{

    SoupContext *ctx;
    SoupMessage *msg = NULL;
    
    ctx = soup_context_get (uri);

    msg = soup_message_new_full (ctx, SOUP_METHOD_POST,
                                 SOUP_BUFFER_USER_OWNED, xml_data,
                                 xml_len);

    soup_context_unref(ctx);
    soup_message_send(msg);

    if (SOUP_ERROR_IS_SUCCESSFUL (msg->errorcode)) {
	    *response_len = msg->response.length;
	    *response = g_strndup (msg->response.body, msg->response.length);
    } else {
        XMLRPC_FAIL(env, msg->errorcode, (char *) msg->errorphrase);
    }
    
cleanup:
    if (msg)
	    soup_message_free (msg);

    if (env->fault_occurred) {
        response_len = 0;
        response = NULL;
    }
}


/******************************************************************************/

typedef struct {
    xmlrpc_server_info *server;
    char *method_name;
    xmlrpc_response_handler callback;
    void *user_data;
    xmlrpc_value *param_array;

    xmlrpc_mem_block *serialized_xml;
} RequestInfo;

static void do_soup_request_async (RequestInfo *info);


void
xmlrpc_client_call_asynch (char *server_url,
                           char *method_name,
                           xmlrpc_response_handler callback,
                           void *user_data,
                           char *format,
                           ...)
{
    xmlrpc_env env;
    va_list args;
    xmlrpc_value *param_array;

    XMLRPC_ASSERT_PTR_OK(format);

    /* Error-handling preconditions. */
    xmlrpc_env_init(&env);
    param_array = NULL;

    /* Build our argument array. */
    va_start(args, format);
    param_array = xmlrpc_build_value_va(&env, format, args);
    va_end(args);
    XMLRPC_FAIL_IF_FAULT(&env);

    /* Perform the actual XML-RPC call. */
    xmlrpc_client_call_asynch_params(server_url, method_name,
                                     callback, user_data, param_array);

cleanup:
    if (env.fault_occurred) {
        (*callback)(server_url, method_name, param_array, user_data,
                    &env, NULL);
    }

    if (param_array)
        xmlrpc_DECREF(param_array);
    xmlrpc_env_clean(&env);
}


void
xmlrpc_client_call_server_asynch (xmlrpc_server_info *server,
                                  char *method_name,
                                  xmlrpc_response_handler callback,
                                  void *user_data,
                                  char *format,
                                  ...)
{
    xmlrpc_env env;
    va_list args;
    xmlrpc_value *param_array;

    XMLRPC_ASSERT_PTR_OK(format);

    /* Error-handling preconditions. */
    xmlrpc_env_init(&env);
    param_array = NULL;

    /* Build our argument array. */
    va_start(args, format);
    param_array = xmlrpc_build_value_va(&env, format, args);
    va_end(args);
    XMLRPC_FAIL_IF_FAULT(&env);

    /* Perform the actual XML-RPC call. */
    xmlrpc_client_call_server_asynch_params(server, method_name,
                                            callback, user_data, param_array);

cleanup:
    if (env.fault_occurred) {
        (*callback)(server->_server_url, method_name, param_array, user_data,
                    &env, NULL);
    }

    if (param_array)
        xmlrpc_DECREF(param_array);
    xmlrpc_env_clean(&env);
}


void
xmlrpc_client_call_asynch_params (char *server_url,
                                  char *method_name,
                                  xmlrpc_response_handler callback,
                                  void *user_data,
                                  xmlrpc_value *param_array)
{
    xmlrpc_env env;
    xmlrpc_server_info *server;

    XMLRPC_ASSERT_PTR_OK(server_url);

    /* Error-handling preconditions. */
    xmlrpc_env_init(&env);
    server = NULL;

    /* Build a server info object and make our call. */
    server = xmlrpc_server_info_new(&env, server_url);
    XMLRPC_FAIL_IF_FAULT(&env);
    xmlrpc_client_call_server_asynch_params(server, method_name,
                                            callback, user_data,
                                            param_array);

cleanup:
    if (server)
        xmlrpc_server_info_free(server);

    if (env.fault_occurred) {
        (*callback)(server_url, method_name, param_array, user_data,
                    &env, NULL);
    }
}

void
xmlrpc_client_call_server_asynch_params (xmlrpc_server_info *server,
                                         char *method_name,
                                         xmlrpc_response_handler callback,
                                         void *user_data,
                                         xmlrpc_value *param_array)
{
    xmlrpc_env env;
    RequestInfo *info;
    xmlrpc_value *mungled_params = NULL;
    xmlrpc_mem_block *xml = NULL;

    XMLRPC_ASSERT_PTR_OK   (server);
    XMLRPC_ASSERT_PTR_OK   (method_name);
    XMLRPC_ASSERT_PTR_OK   (callback);
    XMLRPC_ASSERT_VALUE_OK (param_array);

    xmlrpc_env_init(&env);

    mungled_params = mungle_params (&env, server, param_array);

    xml = xmlrpc_mem_block_new (&env, 0);
    XMLRPC_FAIL_IF_FAULT (&env);
    xmlrpc_serialize_call (&env, xml, method_name, mungled_params);
    XMLRPC_FAIL_IF_FAULT (&env);

    info = g_new0 (RequestInfo, 1);
    info->server = xmlrpc_server_info_copy (server);
    info->method_name = g_strdup (method_name);
    info->callback = callback;
    info->user_data = user_data;

    xmlrpc_INCREF (param_array);
    info->param_array = param_array;

    info->serialized_xml = xml;

    do_soup_request_async (info);

cleanup:
    if (mungled_params)
        xmlrpc_DECREF (mungled_params);

    if (env.fault_occurred) {
        if (xml)
            xmlrpc_mem_block_free (xml);

        /* Report the error immediately. */
        (*callback)(server->_server_url, method_name, param_array, user_data,
                    &env, NULL);
    }

    xmlrpc_env_clean(&env);
}

static void
soup_request_done (SoupMessage *msg, gpointer user_data)
{
    RequestInfo *info = user_data;
    xmlrpc_env env;
    xmlrpc_value *result = NULL;

    xmlrpc_mem_block_free (info->serialized_xml);

    xmlrpc_env_init (&env);

    if (SOUP_ERROR_IS_SUCCESSFUL (msg->errorcode)) {
        result = xmlrpc_parse_response (&env,
                                        msg->response.body,
                                        msg->response.length);
    } else
        xmlrpc_env_set_fault (&env, msg->errorcode, (char *) msg->errorphrase);

    if (info->callback) {
        (*info->callback)(info->server->_server_url,
                          info->method_name,
                          info->param_array,
                          info->user_data,
                          &env,
                          result);
    }

    xmlrpc_DECREF (info->param_array);
    g_free (info->method_name);
    xmlrpc_server_info_free (info->server);
    g_free (info);
    if (result)
        xmlrpc_DECREF (result);

    xmlrpc_env_clean (&env);
}

static void
do_soup_request_async (RequestInfo *info)
{
    SoupContext *ctx;
    SoupMessage *msg;
	
    ctx = soup_context_get (info->server->_server_url);
    msg = soup_message_new_full (ctx, SOUP_METHOD_POST,
                                 SOUP_BUFFER_USER_OWNED,
                                 xmlrpc_mem_block_contents (info->serialized_xml),
                                 xmlrpc_mem_block_size (info->serialized_xml));
    soup_context_unref (ctx);

    soup_message_queue (msg, soup_request_done, info);
}

/*****************************************************************************/

xmlrpc_server_info *
rcd_xmlrpc_get_server (xmlrpc_env *env, const char *host_url)
{
    xmlrpc_server_info *server;
    gchar *url;

    url = g_strdup_printf ("%s/RPC2/redcarpet-client.php", host_url);

    server = xmlrpc_server_info_new (env, url);
    g_free (url);

    xmlrpc_server_info_set_auth (env, server,
                                 rcd_prefs_get_mid (),
                                 rcd_prefs_get_secret ());

    return server;
}

typedef struct {
    gboolean premium_only;
    const char *method_name;
    xmlrpc_response_handler callback;
    void *user_data;
    xmlrpc_value *param_array;
} XmlrpcForeachInfo;

static gboolean
rcd_xmlrpc_foreach_cb (RCWorld *world, gpointer user_data)
{
    RCDWorldRemote *remote = RCD_WORLD_REMOTE (world);
    XmlrpcForeachInfo *info = user_data;
    xmlrpc_env env;
    xmlrpc_server_info *server;

    if (info->premium_only && !remote->premium_service)
        return TRUE;

    xmlrpc_env_init (&env);

    server = rcd_xmlrpc_get_server (&env, RC_WORLD_SERVICE (remote)->url);

    if (env.fault_occurred) {
        rc_debug (RC_DEBUG_LEVEL_WARNING, "Unable to get server for '%s'",
                  RC_WORLD_SERVICE (remote)->url);
        goto cleanup;
    }

    xmlrpc_client_call_server_asynch_params (server,
                                             (char *) info->method_name,
                                             info->callback,
                                             info->user_data,
                                             info->param_array);

    if (env.fault_occurred) {
        rc_debug (RC_DEBUG_LEVEL_WARNING, "Unable to send data to '%s': %s",
                  RC_WORLD_SERVICE (remote)->name, env.fault_string);
    }

cleanup:
    xmlrpc_server_info_free (server);
    xmlrpc_env_clean (&env);

    return TRUE;
}

void
rcd_xmlrpc_client_foreach_host (gboolean premium_only,
                                const char *method_name,
                                xmlrpc_response_handler callback,
                                void *user_data,
                                xmlrpc_value *param_array)
{
    XmlrpcForeachInfo info;

    info.premium_only = premium_only;
    info.method_name = method_name;
    info.callback = callback;
    info.user_data = user_data;
    info.param_array = param_array;

    rc_world_multi_foreach_subworld_by_type (RC_WORLD_MULTI (rc_get_world ()),
                                             RCD_TYPE_WORLD_REMOTE,
                                             rcd_xmlrpc_foreach_cb,
                                             &info);
}
