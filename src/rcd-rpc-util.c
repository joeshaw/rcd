/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include <rc-dep-or.h>

#include "rcd-rpc-util.h"

static void
rcd_rc_package_spec_to_xmlrpc(RCPackageSpec *spec,
                              xmlrpc_value *value,
                              xmlrpc_env *env)
{
    /* RCPackageSpec members */
    RCD_XMLRPC_STRUCT_SET_STRING(
        env, value, "name",
        spec->name);

    RCD_XMLRPC_STRUCT_SET_INT(
        env, value, "epoch",
        spec->epoch);

    RCD_XMLRPC_STRUCT_SET_STRING(
        env, value, "version",
        spec->version);

    RCD_XMLRPC_STRUCT_SET_STRING(
        env, value, "release",
        spec->release);

cleanup:
} /* rcd_rc_package_spec_to_xmlrpc */

xmlrpc_value *
rcd_rc_package_to_xmlrpc (RCPackage *package, xmlrpc_env *env)
{
    xmlrpc_value *value = NULL;

    value = xmlrpc_struct_new(env);
    XMLRPC_FAIL_IF_FAULT(env);

    /* RCPackageSpec members */
    rcd_rc_package_spec_to_xmlrpc(RC_PACKAGE_SPEC(package), value, env);
    XMLRPC_FAIL_IF_FAULT(env);

    /* RCPackage members */
    RCD_XMLRPC_STRUCT_SET_INT(env, value, "installed", package->installed);

    RCD_XMLRPC_STRUCT_SET_INT(
        env, value, "channel",
        package->channel ? rc_channel_get_id(package->channel) : 0);
        
    RCD_XMLRPC_STRUCT_SET_STRING(
        env, value, "package_filename", package->package_filename);

    RCD_XMLRPC_STRUCT_SET_STRING(
        env, value, "signature_filename", package->signature_filename);

cleanup:
    if (env->fault_occurred) {
        if (value)
            xmlrpc_DECREF(value);
        return NULL;
    }

    return value;
} /* rcd_rc_package_to_xmlrpc */

xmlrpc_value *
rcd_rc_package_slist_to_xmlrpc_array(RCPackageSList *rc_packages, 
                                     xmlrpc_env     *env)
{
    xmlrpc_value *package_array;
    RCPackageSList *i;

    package_array = xmlrpc_build_value(env, "()");

    for (i = rc_packages; i; i = i->next) {
        RCPackage *package = i->data;
        xmlrpc_value *value;

        value = rcd_rc_package_to_xmlrpc(package, env);
        XMLRPC_FAIL_IF_FAULT(env);

        xmlrpc_array_append_item(env, package_array, value);
        XMLRPC_FAIL_IF_FAULT(env);

        /*
         * Adding the value to the array increments its refcount, so release
         * our ref and let the array own it.
         */
        xmlrpc_DECREF(value);
    }

cleanup:
    if (env->fault_occurred)
        return NULL;

    return package_array;
} /* rcd_rc_package_slist_to_xmlrpc_array */

RCDQueryPart
rcd_xmlrpc_tuple_to_query_part (xmlrpc_value *tuple, xmlrpc_env *env)
{
    char *key;
    char *type_str;
    char *query_str;
    xmlrpc_bool negate;
    RCDQueryType type;
    RCDQueryPart part;

    xmlrpc_parse_value (
        env, tuple, "(sssb)", 
        &key, &type_str, &query_str, &negate);
    XMLRPC_FAIL_IF_FAULT (env);

    type = rcd_query_type_from_string (type_str);

    part.key = g_strdup (key);
    part.type = type;
    part.query_str = g_strdup (query_str);
    part.negate = (gboolean) negate;

cleanup:
    if (env->fault_occurred) {
        part.type = RCD_QUERY_INVALID;
        part.key = NULL;
        part.query_str = NULL;
    }

    return part;
} /* rcd_xmlrpc_tuple_to_query_part */
    
