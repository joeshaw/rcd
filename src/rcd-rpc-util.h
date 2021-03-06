/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-rpc-util.h
 *
 * Copyright (C) 2002 Ximian, Inc.
 *
 */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
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

#ifndef __RCD_RPC_UTIL_H__
#define __RCD_RPC_UTIL_H__

#include <libredcarpet.h>
#include <xmlrpc.h>

#include "rcd-query.h"

/* Keep these in sync with rcfault.py! */
#define RCD_RPC_FAULT_TYPE_MISMATCH          -501 /* matches xmlrpc-c */
#define RCD_RPC_FAULT_INVALID_STREAM_TYPE    -503 /* matches xmlrpc-c */
#define RCD_RPC_FAULT_PERMISSION_DENIED      -600
#define RCD_RPC_FAULT_PACKAGE_NOT_FOUND      -601
#define RCD_RPC_FAULT_PACKAGE_IS_NEWEST      -602
#define RCD_RPC_FAULT_FAILED_DEPENDENCIES    -603
#define RCD_RPC_FAULT_INVALID_SEARCH_TYPE    -604
#define RCD_RPC_FAULT_INVALID_PACKAGE_FILE   -605
#define RCD_RPC_FAULT_INVALID_CHANNEL        -606
#define RCD_RPC_FAULT_INVALID_TRANSACTION_ID -607
#define RCD_RPC_FAULT_INVALID_PREFERENCE     -608
#define RCD_RPC_FAULT_LOCKED                 -609
#define RCD_RPC_FAULT_CANT_AUTHENTICATE      -610
#define RCD_RPC_FAULT_CANT_REFRESH           -611
#define RCD_RPC_FAULT_NO_ICON                -612
#define RCD_RPC_FAULT_CANT_ACTIVATE          -613
#define RCD_RPC_FAULT_NOT_SUPPORTED          -614
#define RCD_RPC_FAULT_LICENSE_NOT_FOUND      -615
#define RCD_RPC_FAULT_CANT_SET_PREFERENCE    -616
#define RCD_RPC_FAULT_INVALID_SERVICE        -617
#define RCD_RPC_FAULT_TRANSACTION_FAILED     -618

#define is_empty_string(x)     (!(x) || !(*(x)))
#define RC_STRING_TO_XMLRPC(x) ((x) == NULL ? "" : (x))
#define XMLRPC_STRING_TO_RC(x) (is_empty_string((x)) ? NULL : (x))

void          rcd_rc_package_spec_to_xmlrpc(RCPackageSpec *spec,
                                            xmlrpc_value  *value,
                                            xmlrpc_env    *env);

void          rcd_rc_package_dep_to_xmlrpc(RCPackageDep *dep,
                                           xmlrpc_value *value,
                                           xmlrpc_env   *env);

xmlrpc_value *rcd_rc_package_dep_array_to_xmlrpc(RCPackageDepArray *rc_deps,
                                                 xmlrpc_env        *env);

RCPackageSpec *rcd_xmlrpc_to_rc_package_spec(xmlrpc_value *value,
                                             xmlrpc_env   *env);

RCPackageDep *rcd_xmlrpc_to_rc_package_dep(xmlrpc_value *value,
                                           xmlrpc_env   *env);

RCPackageDepSList *rcd_xmlrpc_array_to_rc_package_dep_slist(xmlrpc_value *value,
                                                            xmlrpc_env   *env);

xmlrpc_value *rcd_rc_package_match_to_xmlrpc(RCPackageMatch *match,
                                             xmlrpc_env     *env);

RCPackageMatch *rcd_xmlrpc_to_rc_package_match(xmlrpc_value *value,
                                               xmlrpc_env   *env);

xmlrpc_value *rcd_rc_package_to_xmlrpc(RCPackage  *package, 
                                       xmlrpc_env *env);

xmlrpc_value *rcd_rc_package_slist_to_xmlrpc_array(RCPackageSList *rc_packages,
                                                   xmlrpc_env     *env);

#define RCD_PACKAGE_FROM_NAME             1 << 0
#define RCD_PACKAGE_FROM_FILE             1 << 1
#define RCD_PACKAGE_FROM_STREAMED_PACKAGE 1 << 2
#define RCD_PACKAGE_FROM_XMLRPC_PACKAGE   1 << 3

#define RCD_PACKAGE_FROM_ANY (RCD_PACKAGE_FROM_NAME |             \
                              RCD_PACKAGE_FROM_FILE |             \
                              RCD_PACKAGE_FROM_STREAMED_PACKAGE | \
                              RCD_PACKAGE_FROM_XMLRPC_PACKAGE)


RCPackage      *rcd_rc_package_from_name             (xmlrpc_value *value,
                                                      xmlrpc_env   *env);
RCPackage      *rcd_rc_package_from_file             (xmlrpc_value *value,
                                                      xmlrpc_env   *env);
RCPackage      *rcd_rc_package_from_streamed_package (xmlrpc_value *value,
                                                      xmlrpc_env   *env);
RCPackage      *rcd_rc_package_from_xmlrpc_package   (xmlrpc_value *value,
                                                      xmlrpc_env   *env);

/* Uses any of the above 4 functions to get the package */
RCPackage      *rcd_xmlrpc_to_rc_package             (xmlrpc_value *value,
                                                      xmlrpc_env   *env,
                                                      int           flags);
RCPackageSList *rcd_xmlrpc_array_to_rc_package_slist (xmlrpc_value *value,
                                                      xmlrpc_env   *env,
                                                      int           flags);

/* For RCChannel */
xmlrpc_value *rcd_rc_channel_to_xmlrpc(RCChannel  *channel,
                                       xmlrpc_env *env);

/* RCResolverInfo-related functions */
xmlrpc_value *rcd_rc_resolver_info_to_xmlrpc(RCResolverInfo *info,
                                             xmlrpc_env     *env);

xmlrpc_value *rcd_rc_resolver_context_info_to_xmlrpc_array(RCResolverContext *context,
                                                           RCPackage         *package,
                                                           int                priority,
                                                           xmlrpc_env        *env);

/* For RCDQueryPart */
RCDQueryPart rcd_xmlrpc_tuple_to_query_part (xmlrpc_value *tuple,
                                             xmlrpc_env   *env);


xmlrpc_value *rcd_xmlrpc_package_file_list (RCPackage  *package,
                                            xmlrpc_env *env);

#define RCD_XMLRPC_STRUCT_SET_STRING(env, s, key, string)        \
    do {                                                         \
        xmlrpc_value *member;                                    \
                                                                 \
        member = xmlrpc_build_value(                             \
            (env), "s", RC_STRING_TO_XMLRPC((string)));          \
        XMLRPC_FAIL_IF_FAULT((env));                             \
                                                                 \
        xmlrpc_struct_set_value((env), (s), (key), member);      \
        XMLRPC_FAIL_IF_FAULT((env));                             \
                                                                 \
        xmlrpc_DECREF(member);                                   \
    } while (0)

#define RCD_XMLRPC_STRUCT_SET_INT(env, s, key, i)                \
    do {                                                         \
        xmlrpc_value *member;                                    \
                                                                 \
        member = xmlrpc_build_value((env), "i", (i));            \
        XMLRPC_FAIL_IF_FAULT((env));                             \
                                                                 \
        xmlrpc_struct_set_value((env), (s), (key), member);      \
        XMLRPC_FAIL_IF_FAULT((env));                             \
                                                                 \
        xmlrpc_DECREF(member);                                   \
    } while (0)

#define RCD_XMLRPC_STRUCT_SET_DOUBLE(env, s, key, x)             \
    do {                                                         \
        xmlrpc_value *member;                                    \
                                                                 \
        member = xmlrpc_build_value((env), "d", (x));            \
        XMLRPC_FAIL_IF_FAULT((env));                             \
                                                                 \
        xmlrpc_struct_set_value((env), (s), (key), member);      \
        XMLRPC_FAIL_IF_FAULT((env));                             \
                                                                 \
        xmlrpc_DECREF(member);                                   \
    } while (0)

#define RCD_XMLRPC_STRUCT_GET_STRING(env, s, key, result)        \
    do {                                                         \
        xmlrpc_value *member;                                    \
        char *tmp;                                               \
                                                                 \
        member = xmlrpc_struct_get_value((env), (s), (key));     \
        XMLRPC_FAIL_IF_FAULT((env));                             \
                                                                 \
        xmlrpc_parse_value((env), member, "s", &tmp);            \
                                                                 \
        (result) = g_strdup(XMLRPC_STRING_TO_RC(tmp));           \
    } while (0)

#define RCD_XMLRPC_STRUCT_GET_INT(env, s, key, result)           \
    do {                                                         \
        xmlrpc_value *member;                                    \
                                                                 \
        member = xmlrpc_struct_get_value((env), (s), (key));     \
        XMLRPC_FAIL_IF_FAULT((env));                             \
                                                                 \
        xmlrpc_parse_value((env), member, "i", &(result));       \
    } while (0)

#define RCD_XMLRPC_STRUCT_GET_DOUBLE(env, s, key, result)        \
    do {                                                         \
        xmlrpc_value *member;                                    \
                                                                 \
        member = xmlrpc_struct_get_value((env), (s), (key));     \
        XMLRPC_FAIL_IF_FAULT((env));                             \
                                                                 \
        xmlrpc_parse_value((env), member, "d", &(result));       \
    } while (0)

xmlrpc_value *rcd_xmlrpc_array_copy (xmlrpc_env *env, int n_params, ...);

void rcd_rpc_block_on_pending_list (xmlrpc_env *env,
                                    GSList     *pending_list,
                                    gboolean    fail_if_any,
                                    int         fault_to_throw);

/* For debugging purposes */
void rcd_debug_serialize (xmlrpc_value *v);

#endif /* __RCD_RPC_UTIL_H__ */
