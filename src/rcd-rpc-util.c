/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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
#include "rcd-rpc-util.h"

#include <rc-dep-or.h>

void
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
        env, value, "has_epoch",
        spec->has_epoch);
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

void
rcd_rc_package_dep_to_xmlrpc (RCPackageDep *dep,
                              xmlrpc_value *value,
                              xmlrpc_env   *env)
{
    rcd_rc_package_spec_to_xmlrpc ((RCPackageSpec *)dep, value, env);
    
    RCD_XMLRPC_STRUCT_SET_STRING (env, value, "relation",
                                  rc_package_relation_to_string (dep->relation, 0));
    
 cleanup:
}

RCPackageDep *
rcd_xmlrpc_to_rc_package_dep (xmlrpc_value *value,
                              xmlrpc_env   *env)
{
    RCPackageDep *dep = NULL;
    int has_epoch, epoch;
    char *name = NULL, *version = NULL, *release = NULL, *relation_str = NULL;
    RCPackageRelation relation;

    if (! xmlrpc_struct_has_key (env, value, "name"))
        goto cleanup;
    RCD_XMLRPC_STRUCT_GET_STRING (env, value, "name", name);

    if (! xmlrpc_struct_has_key (env, value, "has_epoch"))
        goto cleanup;
    RCD_XMLRPC_STRUCT_GET_INT (env, value, "has_epoch", has_epoch);
    
    if (! xmlrpc_struct_has_key (env, value, "epoch"))
        goto cleanup;
    RCD_XMLRPC_STRUCT_GET_INT (env, value, "epoch", epoch);

    if (! xmlrpc_struct_has_key (env, value, "version"))
        goto cleanup;
    RCD_XMLRPC_STRUCT_GET_STRING (env, value, "version", version);

    if (! xmlrpc_struct_has_key (env, value, "release"))
        goto cleanup;
    RCD_XMLRPC_STRUCT_GET_STRING (env, value, "release", release);

    if (! xmlrpc_struct_has_key (env, value, "relation"))
        goto cleanup;
    RCD_XMLRPC_STRUCT_GET_STRING (env, value, "relation", relation_str);

    relation = rc_string_to_package_relation (relation_str);
    if (relation == RC_RELATION_INVALID)
        goto cleanup;
    
    dep = rc_package_dep_new (name,
                              has_epoch,
                              epoch,
                              version,
                              release,
                              relation);

 cleanup:
    g_free (name);
    g_free (version);
    g_free (release);
    g_free (relation_str);
    
    return dep;
}

RCPackageDepSList *
rcd_xmlrpc_array_to_rc_package_dep_slist (xmlrpc_value *value,
                                          xmlrpc_env   *env)
{
    RCPackageDepSList *dep_list = NULL;
    int size = 0;
    int i;

    size = xmlrpc_array_size (env, value);
    XMLRPC_FAIL_IF_FAULT (env);

    for (i = 0; i < size; i++) {
        xmlrpc_value *v;
        RCPackageDep *dep;

        v = xmlrpc_array_get_item (env, value, i);
        XMLRPC_FAIL_IF_FAULT (env);

        dep = rcd_xmlrpc_to_rc_package_dep (v, env);
        XMLRPC_FAIL_IF_FAULT (env);

        dep_list = g_slist_prepend (dep_list, dep);
    }

cleanup:
    if (env->fault_occurred) {
        rc_package_dep_slist_free (dep_list);

        return NULL;
    }

    return dep_list;
} /* rcd_xmlrpc_array_to_rc_package_dep_slist */

xmlrpc_value *
rcd_rc_package_to_xmlrpc (RCPackage *package, xmlrpc_env *env)
{
    xmlrpc_value *value = NULL;
    RCPackageUpdate *update;
    gboolean installed;

    value = xmlrpc_struct_new(env);
    XMLRPC_FAIL_IF_FAULT(env);

    /* RCPackageSpec members */
    rcd_rc_package_spec_to_xmlrpc(RC_PACKAGE_SPEC(package), value, env);
    XMLRPC_FAIL_IF_FAULT(env);

    /* RCPackage members */
    RCD_XMLRPC_STRUCT_SET_INT(
        env, value, "channel",
        package->channel ? rc_channel_get_id(package->channel) : 0);
    
    update = rc_package_get_latest_update (package);
    if (update) {
        RCD_XMLRPC_STRUCT_SET_INT(
            env, value,
            "importance_num", (int) update->importance);

        RCD_XMLRPC_STRUCT_SET_STRING(
            env, value,
            "importance_str",
            rc_package_importance_to_string (update->importance));
    }

    /* Extra data useful to a client */
    if (package->installed) {
        RCChannel *guess;

        installed = TRUE; 

        guess = rc_world_guess_package_channel (rc_get_world (),
                                                package);

        if (guess != NULL)
            RCD_XMLRPC_STRUCT_SET_INT(env, value, "channel_guess",
                                      rc_channel_get_id (guess));

    } else {

        RCPackage *sys_pkg;

        sys_pkg = rc_world_get_package (
            rc_get_world(),
            RC_WORLD_SYSTEM_PACKAGES,
            RC_PACKAGE_SPEC(package)->name);

        installed = (sys_pkg != NULL
                     && rc_package_spec_equal (RC_PACKAGE_SPEC(package),
                                               RC_PACKAGE_SPEC(sys_pkg)));
    }
    RCD_XMLRPC_STRUCT_SET_INT(env, value, "installed", installed);
        
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

    /* FIXME: This should probably check EVR too */
    package = rc_world_get_package (world, RC_WORLD_SYSTEM_PACKAGES, name);

    if (!package)
        xmlrpc_env_set_fault (env, -613, "Unable to find package");
    else
        rc_package_ref (package);

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
    int channel_id;
    RCWorld *world = rc_get_world ();
    RCPackage *package = NULL;

    RCD_XMLRPC_STRUCT_GET_STRING (env, value, "name", name);
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_GET_INT (env, value, "channel", channel_id);
    XMLRPC_FAIL_IF_FAULT (env);

    if (channel_id) {
        RCChannel *channel;

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
    else {
        package = rc_world_get_package (world, RC_WORLD_SYSTEM_PACKAGES, name);

        if (!package) {
            xmlrpc_env_set_fault (env, -611, "Unable to find package");
            return NULL;
        }
    }

    rc_package_ref (package);

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
    
void
rcd_debug_serialize (xmlrpc_value *v)
{
    xmlrpc_env env;
    xmlrpc_mem_block *output;
    char *output_text;

    xmlrpc_env_init (&env);

    output = xmlrpc_mem_block_new (&env, 0);
    xmlrpc_serialize_value (&env, output, v);

    output_text = g_strndup (
        XMLRPC_TYPED_MEM_BLOCK_CONTENTS (char, output),
        XMLRPC_TYPED_MEM_BLOCK_SIZE (char, output));

    printf("Serialized value %p:\n%s\n-----\n", v, output_text);

    g_free (output_text);
    xmlrpc_mem_block_free (output);
    xmlrpc_env_clean (&env);
} /* rcd_debug_serialize */
