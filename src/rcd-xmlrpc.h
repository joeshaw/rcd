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

#ifndef  _REDCARPET_XMLRPC_SOUP_H_
#define  _REDCARPET_XMLRPC_SOUP_H_ 1

#include "xmlrpc.h"

/*=========================================================================
**  xmlrpc_server_info
**=========================================================================
**  We normally refer to servers by URL. But sometimes we need to do extra
**  setup for particular servers. In that case, we can create an
**  xmlrpc_server_info object, configure it in various ways, and call the
**  remote server.
**
**  (This interface is also designed to discourage further multiplication
**  of xmlrpc_client_call APIs. We have enough of those already. Please
**  add future options and flags using xmlrpc_server_info.)
*/

#ifndef XMLRPC_WANT_INTERNAL_DECLARATIONS

typedef struct _xmlrpc_server_info xmlrpc_server_info;

#else /* XMLRPC_WANT_INTERNAL_DECLARATIONS */

typedef struct _xmlrpc_server_info {
    char *_server_url;
    char *_username;
    char *_password;
} xmlrpc_server_info;

#endif /* XMLRPC_WANT_INTERNAL_DECLARATIONS */

/* Create a new server info record, pointing to the specified server. */
extern xmlrpc_server_info *
xmlrpc_server_info_new (xmlrpc_env *env,
				    const char *server_url);

/* Delete a server info record. */
extern void
xmlrpc_server_info_free (xmlrpc_server_info *server);

/* We support rudimentary basic authentication. This lets us talk to Zope
** servers and similar critters. When called, this routine makes a copy
** of all the authentication information and passes it to future requests.
** Only the most-recently-set authentication information is used.
** (In general, you shouldn't write XML-RPC servers which require this
** kind of authentication--it confuses many client implementations.)
** If we fail, leave the xmlrpc_server_info record unchanged. */
extern void
xmlrpc_server_info_set_auth (xmlrpc_env *env,
					    xmlrpc_server_info *server,
					    const char *username,
					    const char *password);


extern xmlrpc_value * xmlrpc_client_call (xmlrpc_env *env,
					       char *server_url,
					       char *method_name,
					       char *format,
					       ...);

extern xmlrpc_value * xmlrpc_client_call_server (xmlrpc_env *env,
						      xmlrpc_server_info *server,
						      char *method_name,
						      char *format,
						      ...);

extern xmlrpc_value * xmlrpc_client_call_params (xmlrpc_env *env,
						      char *server_url,
						      char *method_name,
						      xmlrpc_value *param_array);

extern xmlrpc_value *xmlrpc_client_call_server_params (xmlrpc_env *env,
							    xmlrpc_server_info *server,
							    char *method_name,
							    xmlrpc_value *param_array);

/* A callback function to handle the response to an asynchronous call.
** If 'fault->fault_occurred' is true, then response will be NULL. All
** arguments except 'user_data' will be deallocated internally; please do
** not free any of them yourself.
** WARNING: param_array may (or may not) be NULL if fault->fault_occurred
** is true, and you set up the call using xmlrpc_client_call_asynch.
** WARNING: If asynchronous calls are still pending when the library is
** shut down, your handler may (or may not) be called with a fault. */
typedef void (*xmlrpc_response_handler) (char *server_url,
					 char *method_name,
					 xmlrpc_value *param_array,
					 void *user_data,
					 xmlrpc_env *fault,
					 xmlrpc_value *result);

/* Make an asynchronous XML-RPC call. We make internal copies of all
** arguments except user_data, so you can deallocate them safely as soon
** as you return. Errors will be passed to the callback. You will need
** to run the event loop somehow; see below.
** WARNING: If an error occurs while building the parameter array, the
** response handler will be called with a NULL param_array. */
extern void
xmlrpc_client_call_asynch (char *server_url,
			   char *method_name,
			   xmlrpc_response_handler callback,
			   void *user_data,
			   char *args_format,
			   ...);

/* As above, but use an xmlrpc_server_info object. The server object can be
** safely destroyed as soon as this function returns. */
extern void
xmlrpc_client_call_server_asynch (xmlrpc_server_info *server,
				  char *method_name,
				  xmlrpc_response_handler callback,
				  void *user_data,
				  char *args_format,
				  ...);

/* As above, but the parameter list is supplied as an xmlrpc_value
** containing an array. We make our own reference to the param_array,
** so you can DECREF yours as soon as this function returns. */
extern void
xmlrpc_client_call_asynch_params (char *server_url,
				  char *method_name,
				  xmlrpc_response_handler callback,
				  void *user_data,
				  xmlrpc_value *param_array);

/* As above, but use an xmlrpc_server_info object. The server object can be
** safely destroyed as soon as this function returns. */
extern void
xmlrpc_client_call_server_asynch_params (xmlrpc_server_info *server,
					 char *method_name,
					 xmlrpc_response_handler callback,
					 void *user_data,
					 xmlrpc_value *param_array);


xmlrpc_server_info *rcd_xmlrpc_get_server (xmlrpc_env *env,
					   const char *host_url);


#endif /* _REDCARPET_XMLRPC_SOUP_H_ */
