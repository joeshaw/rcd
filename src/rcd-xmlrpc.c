/* Copyright (C) 2003 by Ximian, Inc. All rights reserved.
 *
 * Derived from xmlrpc-c/src/xmlrpc_client.c
 */

#include <stdlib.h>
#include <string.h>
#include <libsoup/soup.h>
#include <rc-md5.h>

#define  XMLRPC_WANT_INTERNAL_DECLARATIONS
#include "rcd-xmlrpc.h"
#include "rcd-prefs.h"

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
	g_return_if_fail (server != NULL);
	g_return_if_fail (username != NULL);
	g_return_if_fail (password != NULL);

	if (server->_username)
		g_free (server->_username);
	server->_username = g_strdup (username);

	if (server->_password)
		g_free (server->_password);
	server->_password = rc_md5_digest_from_string (password);
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

xmlrpc_value * xmlrpc_client_call (xmlrpc_env *env,
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

xmlrpc_value * xmlrpc_client_call_server (xmlrpc_env *env,
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

xmlrpc_value * xmlrpc_client_call_params (xmlrpc_env *env,
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

xmlrpc_value *xmlrpc_client_call_server_params (xmlrpc_env *env,
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


void xmlrpc_client_call_asynch (char *server_url,
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


void xmlrpc_client_call_server_asynch (xmlrpc_server_info *server,
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


void xmlrpc_client_call_asynch_params (char *server_url,
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
		XMLRPC_FAIL_IF_FAULT (&env);
	} else
		xmlrpc_env_set_fault (&env, msg->errorcode, (char *) msg->errorphrase);

	(*info->callback)(info->server->_server_url,
				   info->method_name,
				   info->param_array,
				   info->user_data,
				   &env,
				   result);

cleanup:
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

xmlrpc_server_info *
rcd_xmlrpc_get_server (xmlrpc_env *env)
{
	xmlrpc_server_info *server;
	gchar *url;

	url = g_strdup_printf ("%s/RPC2/redcarpet-client.php",
					   rcd_prefs_get_host ());

	server = xmlrpc_server_info_new (env, url);
	g_free (url);

	xmlrpc_server_info_set_auth (env, server,
						    rcd_prefs_get_mid (),
						    rcd_prefs_get_secret ());

	return server;
}
