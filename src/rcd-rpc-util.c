/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include <config.h>
#include "rcd-rpc-util.h"

#include <rc-dep-or.h>

static void
rcd_rc_package_spec_to_xmlrpc(RCPackageSpec *spec,
                              xmlrpc_value *value,
                              xmlrpc_env *env)
{
    /* RCPackageSpec members */
    RCD_XMLRPC_STRUCT_SET_STRING(
        env, value, "name",
        spec->name);
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_SET_INT(
        env, value, "epoch",
        spec->epoch);
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_SET_STRING(
        env, value, "version",
        spec->version);
    XMLRPC_FAIL_IF_FAULT (env);

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

RCPackage *
rcd_rc_package_from_name (xmlrpc_value *value,
                          xmlrpc_env   *env)
{
    char *name;
    RCWorld *world = rc_get_world ();
    RCPackage *package = NULL;

    xmlrpc_parse_value (env, value, "s", &name);
    XMLRPC_FAIL_IF_FAULT (env);

    package = rc_world_get_package (world, RC_WORLD_ANY_CHANNEL, name);

    if (!package)
        xmlrpc_env_set_fault (env, -613, "Unable to find package");

cleanup:
    return package;
} /* rcd_rc_package_from_name */

RCPackage *
rcd_rc_package_from_file (xmlrpc_value *value,
                          xmlrpc_env   *env)
{
    char *file_name;
    RCWorld *world = rc_get_world ();
    RCPackman *packman = rc_world_get_packman (world);
    RCPackage *package = NULL;

    xmlrpc_parse_value (env, value, "s", &file_name);
    XMLRPC_FAIL_IF_FAULT (env);

    package = rc_packman_query_file (packman, file_name);

    if (package)
        package->package_filename = g_strdup (file_name);
    else
        xmlrpc_env_set_fault (env, -613, "Unable to find package");

cleanup:
    return package;
} /* rcd_rc_package_from_file */

RCPackage *
rcd_rc_package_from_streamed_package (xmlrpc_value *value,
                                      xmlrpc_env   *env)
{
    char *file_name;
    char *package_file;
    size_t package_size;
    int fd;
    RCWorld *world = rc_get_world ();
    RCPackman *packman = rc_world_get_packman (world);
    RCPackage *package = NULL;

    xmlrpc_parse_value (env, value, "6", &package_file, &package_size);
    XMLRPC_FAIL_IF_FAULT (env);

    fd = g_file_open_tmp ("package-XXXXXX", &file_name, NULL);
    rc_write (fd, package_file, package_size);
    rc_close (fd);

    package = rc_packman_query_file (packman, file_name);

    if (package)
        package->package_filename = file_name;
    else {
        xmlrpc_env_set_fault (env, -614, "Unable to read package");
        g_free (file_name);
    }

cleanup:
    return package;
} /* rcd_rc_package_from_streamed_package */

RCPackage *
rcd_rc_package_from_xmlrpc_package (xmlrpc_value *value,
                                    xmlrpc_env   *env)
{
    char *name;
    gboolean installed;
    RCWorld *world = rc_get_world ();
    RCPackage *package = NULL;

    RCD_XMLRPC_STRUCT_GET_STRING (env, value, "name", name);
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_GET_INT (env, value, "installed", installed);
    XMLRPC_FAIL_IF_FAULT (env);

    if (installed) {
        package = rc_world_get_package (world, RC_WORLD_SYSTEM_PACKAGES, name);

        if (!package) {
            xmlrpc_env_set_fault (env, -611, "Unable to find package");
            return NULL;
        }

        return package;
    }
    else {
        int channel_id;
        RCChannel *channel;

        RCD_XMLRPC_STRUCT_GET_INT (env, value, "channel", channel_id);
        XMLRPC_FAIL_IF_FAULT (env);

        channel = rc_world_get_channel_by_id (world, channel_id);
        if (!channel) {
            xmlrpc_env_set_fault (env, -612, "Unable to find channel");
            return NULL;
        }

        package = rc_world_get_package (world, channel, name);
        if (!package) {
            xmlrpc_env_set_fault (env, -611, "Unable to find package");
            return NULL;
        }
    }

cleanup:
    return package;
} /* rcd_rc_package_from_xmlrpc_package */

RCPackage *
rcd_xmlrpc_to_rc_package (xmlrpc_value *value,
                          xmlrpc_env   *env,
                          int           flags)
{
    RCPackage *package = NULL;

    if (flags & RCD_PACKAGE_FROM_XMLRPC_PACKAGE &&
        xmlrpc_value_type (value) == XMLRPC_TYPE_STRUCT)
        package = rcd_rc_package_from_xmlrpc_package (value, env);
    else if (flags & RCD_PACKAGE_FROM_STREAMED_PACKAGE &&
             xmlrpc_value_type (value) == XMLRPC_TYPE_BASE64)
        package = rcd_rc_package_from_streamed_package (value, env);
    else if (xmlrpc_value_type (value) == XMLRPC_TYPE_STRING) {
        if (flags & RCD_PACKAGE_FROM_NAME)
            package = rcd_rc_package_from_name (value, env);

        if (flags & RCD_PACKAGE_FROM_FILE && !package) {
            xmlrpc_env_clean (env);
            xmlrpc_env_init (env);
            
            package = rcd_rc_package_from_file (value, env);
        }
    }
    else
        xmlrpc_env_set_fault(env, -503, "Invalid package stream type");

    return package;
} /* rcd_xmlrpc_to_rc_package */

RCPackageSList *
rcd_xmlrpc_array_to_rc_package_slist (xmlrpc_value *value,
                                      xmlrpc_env   *env,
                                      int           flags)
{
    RCPackageSList *package_list = NULL;
    int size = 0;
    int i;

    size = xmlrpc_array_size (env, value);
    XMLRPC_FAIL_IF_FAULT (env);

    for (i = 0; i < size; i++) {
        xmlrpc_value *v;
        RCPackage *package;

        v = xmlrpc_array_get_item (env, value, i);
        XMLRPC_FAIL_IF_FAULT (env);

        package = rcd_xmlrpc_to_rc_package (v, env, flags);
        XMLRPC_FAIL_IF_FAULT (env);

        package_list = g_slist_prepend (package_list, package);
    }

cleanup:
    if (env->fault_occurred) {
        rc_package_slist_unref (package_list);
        g_slist_free (package_list);

        return NULL;
    }

    return package_list;
} /* rcd_xmlrpc_array_to_rc_package_slist */

xmlrpc_value *
rcd_rc_channel_to_xmlrpc (RCChannel  *channel,
                          xmlrpc_env *env)
{
    xmlrpc_value *value;
    
    g_return_val_if_fail (channel != NULL, NULL);

    value = xmlrpc_struct_new (env);
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_SET_INT (env, value, "id", rc_channel_get_id (channel));
    
    RCD_XMLRPC_STRUCT_SET_STRING (env, value, "name", rc_channel_get_name (channel));

    RCD_XMLRPC_STRUCT_SET_INT (env, value, "subscribed",
                               rc_channel_subscribed (channel) ? 1 : 0);

    if (env->fault_occurred) {
        if (value)
            xmlrpc_DECREF (value);
        return NULL;
    }

 cleanup:
    if (env->fault_occurred)
        return NULL;

    return value;
}

RCDQueryPart
rcd_xmlrpc_tuple_to_query_part (xmlrpc_value *tuple, xmlrpc_env *env)
{
    char *key;
    char *type_str;
    char *query_str;
    RCDQueryType type;
    RCDQueryPart part;

    xmlrpc_parse_value (
        env, tuple, "(sss)", 
        &key, &type_str, &query_str);
    XMLRPC_FAIL_IF_FAULT (env);

    type = rcd_query_type_from_string (type_str);

    part.key = g_strdup (key);
    part.type = type;
    part.query_str = g_strdup (query_str);

cleanup:
    if (env->fault_occurred) {
        part.type = RCD_QUERY_INVALID;
        part.key = NULL;
        part.query_str = NULL;
    }

    return part;
} /* rcd_xmlrpc_tuple_to_query_part */
    
