/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#ifndef __RCD_RPC_UTIL_H__
#define __RCD_RPC_UTIL_H__

#include <libredcarpet.h>
#include <xmlrpc.h>

#include "rcd-query.h"

#define is_empty_string(x)     (!(x) || !(*(x)))
#define RC_STRING_TO_XMLRPC(x) ((x) == NULL ? "" : (x))
#define XMLRPC_STRING_TO_RC(x) (is_empty_string((x)) ? NULL : (x))


xmlrpc_value *rcd_rc_package_to_xmlrpc(RCPackage  *package, 
                                       xmlrpc_env *env);

xmlrpc_value *rcd_rc_package_slist_to_xmlrpc_array(RCPackageSList *rc_packages,
                                                   xmlrpc_env     *env);

RCPackage    *rcd_xmlrpc_streamed_to_rc_package (RCPackman    *packman,
                                                 xmlrpc_value *value,
                                                 xmlrpc_env   *env);

xmlrpc_value *rcd_rc_channel_to_xmlrpc(RCChannel  *channel,
                                       xmlrpc_env *env);

RCDQueryPart rcd_xmlrpc_tuple_to_query_part (xmlrpc_value *tuple,
                                             xmlrpc_env   *env);


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

#define DEBUG_SERIALIZE(v)                              \
{                                                       \
    xmlrpc_env        env;                              \
    xmlrpc_mem_block *output;                           \
    char *output_text;                                  \
                                                        \
    xmlrpc_env_init(&env);                              \
                                                        \
    output = xmlrpc_mem_block_new(&env, 0);             \
    xmlrpc_serialize_value(&env, output, (v));          \
                                                        \
    output_text = g_strndup(                            \
        XMLRPC_TYPED_MEM_BLOCK_CONTENTS(char, output),  \
        XMLRPC_TYPED_MEM_BLOCK_SIZE(char, output));     \
                                                        \
    printf("Debug:\n%s\n-----\n", output_text);         \
                                                        \
    g_free(output_text);                                \
    xmlrpc_mem_block_free(output);                      \
    xmlrpc_env_clean(&env);                             \
}

#endif /* __RCD_RPC_UTIL_H__ */
