/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-rpc-util.c
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
        g_quark_to_string (spec->nameq));
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
    ;
} /* rcd_rc_package_spec_to_xmlrpc */

void
rcd_rc_package_dep_to_xmlrpc (RCPackageDep *dep,
                              xmlrpc_value *value,
                              xmlrpc_env   *env)
{
    RCChannel *channel;

    rcd_rc_package_spec_to_xmlrpc ((RCPackageSpec *)dep, value, env);
    
    RCD_XMLRPC_STRUCT_SET_STRING (
        env, value, "relation",
        rc_package_relation_to_string (rc_package_dep_get_relation (dep), 0));

    channel = rc_package_dep_get_channel (dep);

    if (!rc_channel_is_wildcard (channel)) {
        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "channel",
                                      rc_channel_get_id (channel));
    }
    
 cleanup:
    ;
}

xmlrpc_value *
rcd_rc_package_dep_array_to_xmlrpc (RCPackageDepArray *rc_deps,
                                    xmlrpc_env        *env)
{
    xmlrpc_value *dep_array;
    int i;

    dep_array = xmlrpc_build_value (env, "()");
    
    for (i = 0; rc_deps != NULL && i < rc_deps->len; i++) {
        xmlrpc_value *dep_value;

        dep_value = xmlrpc_struct_new (env);
        rcd_rc_package_dep_to_xmlrpc (rc_deps->data[i], dep_value, env);
        xmlrpc_array_append_item (env, dep_array, dep_value);
        xmlrpc_DECREF (dep_value);
    }

    return dep_array;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static gboolean
assemble_spec (xmlrpc_value  *value,
               xmlrpc_env    *env,
               RCPackageSpec *spec)
{
    gboolean success = FALSE;
    int has_epoch, epoch;
    char *name = NULL, *version = NULL, *release = NULL, *version_str = NULL;

    if (! xmlrpc_struct_has_key (env, value, "name"))
        goto cleanup;
    RCD_XMLRPC_STRUCT_GET_STRING (env, value, "name", name);

    if (xmlrpc_struct_has_key (env, value, "version_str")) {

        RCPackman *packman = rc_packman_get_global ();

        RCD_XMLRPC_STRUCT_GET_STRING (env, value, "version_str", version_str);

        if (! rc_packman_parse_version (packman, version_str,
                                        &has_epoch,
                                        &epoch,
                                        &version,
                                        &release))
            goto cleanup;

    } else {

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
    }

    rc_package_spec_init (spec, name, has_epoch, epoch, version, release);

    success = TRUE;

 cleanup:
    g_free (name);
    g_free (version);
    g_free (release);
    g_free (version_str);

    return success;
}

RCPackageSpec *
rcd_xmlrpc_to_rc_package_spec (xmlrpc_value *value,
                               xmlrpc_env   *env)
{
    RCPackageSpec *spec = g_new0 (RCPackageSpec, 1);

    if (! assemble_spec (value, env, spec)) {
        g_free (spec);
        return NULL;
    }

    return spec;
}

RCPackageDep *
rcd_xmlrpc_to_rc_package_dep (xmlrpc_value *value,
                              xmlrpc_env   *env)
{
    RCPackageSpec spec;
    const char *name;
    gboolean is_or;
    RCPackageDep *dep = NULL;
    char *relation_str = NULL;
    RCPackageRelation relation;
    char *channel_id;
    RCChannel *channel = RC_CHANNEL_ANY;

    if (! assemble_spec (value, env, &spec))
        return NULL;

    /* Check to see if this is an or dep */
    name = g_quark_to_string (spec.nameq);
    if (strncmp (name, "(||", 3) == 0)
        is_or = TRUE;
    else
        is_or = FALSE;

    if (! xmlrpc_struct_has_key (env, value, "relation")) {
        XMLRPC_FAIL (env, RCD_RPC_FAULT_TYPE_MISMATCH,
                     "No dependency relation provided");
    }
    RCD_XMLRPC_STRUCT_GET_STRING (env, value, "relation", relation_str);

    relation = rc_package_relation_from_string (relation_str);
    if (relation == RC_RELATION_INVALID) {
        XMLRPC_FAIL (env, RCD_RPC_FAULT_TYPE_MISMATCH,
                     "Invalid dependency relation provided");
    }

    if (xmlrpc_struct_has_key (env, value, "channel")) {
        RCD_XMLRPC_STRUCT_GET_STRING (env, value, "channel", channel_id);

        channel = rc_world_get_channel_by_id (rc_get_world (), channel_id);

        if (!channel) {
            XMLRPC_FAIL (env, RCD_RPC_FAULT_INVALID_CHANNEL,
                         "Invalid channel");
        }
    }
    
    dep = rc_package_dep_new_from_spec (&spec, relation, channel,
                                        FALSE, is_or);

 cleanup:
    rc_package_spec_free_members (&spec);
    g_free (relation_str);
    
    return dep;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

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

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

xmlrpc_value *
rcd_rc_package_match_to_xmlrpc (RCPackageMatch *match,
                                xmlrpc_env     *env)
{
    xmlrpc_value *value = NULL;

    g_return_val_if_fail (match != NULL, NULL);

    value = xmlrpc_struct_new (env);
    XMLRPC_FAIL_IF_FAULT (env);

    if (rc_package_match_get_dep (match) != NULL) {

        xmlrpc_value *dep_value = xmlrpc_struct_new (env);
        rcd_rc_package_dep_to_xmlrpc (rc_package_match_get_dep (match),
                                      dep_value, env);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_struct_set_value (env, value, "dep", dep_value);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_DECREF (dep_value);
    }

    if (rc_package_match_get_glob (match) != NULL) {
        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "glob",
                                      rc_package_match_get_glob (match));
    }

    if (rc_package_match_get_channel_id (match) != NULL) {
        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "channel",
                                      rc_package_match_get_channel_id (match));
    }

    if (rc_package_match_get_importance (match, NULL) != RC_IMPORTANCE_INVALID) {
        RCPackageImportance imp;
        gboolean imp_gteq;
        imp = rc_package_match_get_importance (match, &imp_gteq);
        RCD_XMLRPC_STRUCT_SET_INT (env, value, "importance_num",
                                   (gint) imp);
        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "importance_str",
                                      rc_package_importance_to_string (imp));
        RCD_XMLRPC_STRUCT_SET_INT (env, value, "importance_gteq", imp_gteq);
    }

 cleanup:
    if (env->fault_occurred) /* FIXME: leaks */
        return NULL;

    return value;
}

RCPackageMatch *
rcd_xmlrpc_to_rc_package_match (xmlrpc_value *value,
                                xmlrpc_env   *env)
{
    RCPackageMatch *match;
    char *glob = NULL;
    char *cid;
    gboolean did_something = FALSE;
    
    g_return_val_if_fail (value != NULL, NULL);
    g_return_val_if_fail (env != NULL, NULL);

    match = rc_package_match_new ();

    if (xmlrpc_struct_has_key (env, value, "dep")) {

        RCPackageDep *dep;
        xmlrpc_value *dep_value;
        dep_value = xmlrpc_struct_get_value (env, value, "dep");
        XMLRPC_FAIL_IF_FAULT (env);

        dep = rcd_xmlrpc_to_rc_package_dep (dep_value, env);
        XMLRPC_FAIL_IF_FAULT (env);

        rc_package_match_set_dep (match, dep);
        rc_package_dep_unref (dep);
        did_something = TRUE;
    }
    XMLRPC_FAIL_IF_FAULT (env);

    if (xmlrpc_struct_has_key (env, value, "glob")) {

        RCD_XMLRPC_STRUCT_GET_STRING (env, value, "glob", glob);
        if (glob && *glob) {
            rc_package_match_set_glob (match, glob);
            did_something = TRUE;
        }
    }
    XMLRPC_FAIL_IF_FAULT (env);

    if (xmlrpc_struct_has_key (env, value, "channel")) {

        RCChannel *channel;
        RCD_XMLRPC_STRUCT_GET_STRING (env, value, "channel", cid);
        channel = rc_world_get_channel_by_id (rc_get_world (), cid);
        if (channel) {
            rc_package_match_set_channel (match, channel);
            did_something = TRUE;
        } else
            rc_debug (RC_DEBUG_LEVEL_WARNING,
                      "Unknown channel '%s' in match", cid);
    }
    XMLRPC_FAIL_IF_FAULT (env);

    if (xmlrpc_struct_has_key (env, value, "importance_str")
        || xmlrpc_struct_has_key (env, value, "importance_num")) {

        RCPackageImportance imp;
        gint imp_gteq = 1;

        if (xmlrpc_struct_has_key (env, value, "importance_str")) {
            char *imp_str;
            RCD_XMLRPC_STRUCT_GET_STRING (env, value, "importance_str",
                                          imp_str);
            imp = rc_string_to_package_importance (imp_str);
            g_free (imp_str);
        } else { /* has_key "importance_num" */
            RCD_XMLRPC_STRUCT_GET_INT (env, value, "importance_num", imp);
        }

        if (xmlrpc_struct_has_key (env, value, "importance_gteq")) {
            RCD_XMLRPC_STRUCT_GET_INT (env, value, "importance_gteq",
                                       imp_gteq);
        }

        rc_package_match_set_importance (match, imp, imp_gteq);

        did_something = TRUE;
    }
    XMLRPC_FAIL_IF_FAULT (env);

    if (! did_something) {
        rc_package_match_free (match);
        match = NULL;
    }

 cleanup:
    if (env->fault_occurred) {
        rc_package_match_free (match);
        match = NULL;
    }
    g_free (glob);
    
    return match;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

struct InstalledFlags {
    RCPackage *pkg;
    int installed;
    int name_installed;
};

static gboolean
installed_check_cb (RCPackage *sys_pkg,
                    gpointer user_data)
{
    struct InstalledFlags *flags = user_data;
    int cmp;
    
    cmp = rc_packman_version_compare (rc_packman_get_global (),
                                      RC_PACKAGE_SPEC (flags->pkg),
                                      RC_PACKAGE_SPEC (sys_pkg));

    if (cmp == 0) {

        flags->installed = 1;

    } else {

        if (! flags->name_installed)
            flags->name_installed = cmp;
        else
            flags->name_installed = MAX (flags->name_installed, cmp);
    }

    return TRUE;
}

xmlrpc_value *
rcd_rc_package_to_xmlrpc (RCPackage *package, xmlrpc_env *env)
{
    xmlrpc_value *value = NULL;
    RCPackageUpdate *update;
    gboolean installed;
    gint name_installed;

    value = xmlrpc_struct_new(env);
    XMLRPC_FAIL_IF_FAULT(env);

    /* RCPackageSpec members */
    rcd_rc_package_spec_to_xmlrpc(RC_PACKAGE_SPEC(package), value, env);
    XMLRPC_FAIL_IF_FAULT(env);

    /* RCPackage members */
    RCD_XMLRPC_STRUCT_SET_STRING(
        env, value, "channel",
        package->channel && !rc_channel_is_hidden (package->channel) ?
        rc_channel_get_id (package->channel) : "");
    
    update = rc_package_get_latest_update (package);
    if (update) {
        RCD_XMLRPC_STRUCT_SET_INT(
            env, value,
            "importance_num", (int) update->importance);

        RCD_XMLRPC_STRUCT_SET_STRING(
            env, value,
            "importance_str",
            rc_package_importance_to_string (update->importance));

        if (update->license) {
            RCD_XMLRPC_STRUCT_SET_STRING (env, value,
                                          "license", update->license);
        }
    }

    /* Extra data useful to a client */

    RCD_XMLRPC_STRUCT_SET_INT(
        env, value,
        "package_set", rc_package_is_package_set (package));

    RCD_XMLRPC_STRUCT_SET_INT(
        env, value,
        "file_size", package->file_size);

    RCD_XMLRPC_STRUCT_SET_INT(
        env, value,
        "installed_size", package->installed_size);

    RCD_XMLRPC_STRUCT_SET_STRING(
        env, value,
        "section_str", rc_package_section_to_string (package->section));

    RCD_XMLRPC_STRUCT_SET_STRING(
        env, value,
        "section_user_str", rc_package_section_to_user_string (package->section));

    RCD_XMLRPC_STRUCT_SET_INT(
        env, value,
        "section_num", package->section);

    if (rc_package_is_installed (package)) {
        RCChannel *guess;

        installed = TRUE; 

        guess = rc_world_guess_package_channel (rc_get_world (),
                                                package);

        if (guess != NULL)
            RCD_XMLRPC_STRUCT_SET_STRING(env, value, "channel_guess",
                                         rc_channel_get_id (guess));

        name_installed = 1;

    } else {
        const char *name;
        struct InstalledFlags flags;
        flags.pkg = package;
        flags.installed = 0;
        flags.name_installed = 0;

        name = g_quark_to_string (RC_PACKAGE_SPEC (package)->nameq);
        rc_world_foreach_package_by_name (rc_get_world (),
                                          name,
                                          RC_CHANNEL_SYSTEM,
                                          installed_check_cb,
                                          &flags);
        
        installed = flags.installed;
        name_installed = flags.name_installed;
    }
    RCD_XMLRPC_STRUCT_SET_INT(env, value, "installed", installed);
    RCD_XMLRPC_STRUCT_SET_INT(env, value, "name_installed", name_installed);

    RCD_XMLRPC_STRUCT_SET_INT(env, value, "locked",
                              rc_world_package_is_locked (rc_get_world (), package) ? 1 : 0);
        
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
    package = rc_world_get_package (world, RC_CHANNEL_SYSTEM, name);

    if (!package)
        xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PACKAGE_NOT_FOUND,
                              "Unable to find package");
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
    RCPackman *packman = rc_packman_get_global ();
    RCPackage *package = NULL;

    xmlrpc_parse_value (env, value, "s", &file_name);
    XMLRPC_FAIL_IF_FAULT (env);

    package = rc_packman_query_file (packman, file_name);

    if (package)
        package->package_filename = g_strdup (file_name);
    else
        xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PACKAGE_NOT_FOUND,
                              "Unable to find package");

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
    RCPackman *packman = rc_packman_get_global ();
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
        xmlrpc_env_set_fault (env, RCD_RPC_FAULT_INVALID_PACKAGE_FILE,
                              "Unable to read package");
        g_free (file_name);
    }

cleanup:
    return package;
} /* rcd_rc_package_from_streamed_package */

RCPackage *
rcd_rc_package_from_xmlrpc_package (xmlrpc_value *value,
                                    xmlrpc_env   *env)
{
    char *name = NULL;
    int has_key;
    char *channel_id;
    RCWorld *world = rc_get_world ();
    RCPackman *packman = rc_packman_get_global ();
    RCPackage *package = NULL;

    has_key = xmlrpc_struct_has_key (env, value, "package_data");
    XMLRPC_FAIL_IF_FAULT (env);

    if (has_key) {
        xmlrpc_value *package_data = xmlrpc_struct_get_value (
            env, value, "package_data");
        XMLRPC_FAIL_IF_FAULT (env);
        
        package = rcd_rc_package_from_streamed_package (package_data, env);
        XMLRPC_FAIL_IF_FAULT (env);
        
        return package;
    }
    
    has_key = xmlrpc_struct_has_key (env, value, "package_filename");
    XMLRPC_FAIL_IF_FAULT (env);
    
    if (has_key) {
        char *filename;
        
        RCD_XMLRPC_STRUCT_GET_STRING (env, value, "package_filename",
                                      filename);
        XMLRPC_FAIL_IF_FAULT (env);
        
        package = rc_packman_query_file (packman, filename);
        
        if (package)
            package->package_filename = g_strdup (filename);
        else
            xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PACKAGE_NOT_FOUND,
                                  "Unable to find package");
        
        g_free (filename);
        
        return package;
    }

    RCD_XMLRPC_STRUCT_GET_STRING (env, value, "name", name);
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_GET_STRING (env, value, "channel", channel_id);
    XMLRPC_FAIL_IF_FAULT (env);

    if (channel_id) {
        RCChannel *channel;
        
        channel = rc_world_get_channel_by_id (world, channel_id);
        if (!channel) {
            xmlrpc_env_set_fault (env, RCD_RPC_FAULT_INVALID_CHANNEL,
                                  "Unable to find channel");
            goto cleanup;
        }

        package = rc_world_get_package (world, channel, name);
        if (!package) {
            xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PACKAGE_NOT_FOUND,
                                  "Unable to find package");
            goto cleanup;
        }
    }
    else {
        package = rc_world_get_package (world, RC_CHANNEL_SYSTEM, name);

        if (!package) {
            xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PACKAGE_NOT_FOUND,
                                  "Unable to find package");
            goto cleanup;
        }
    }

    rc_package_ref (package);

cleanup:
    g_free (name);

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
        xmlrpc_env_set_fault(env, RCD_RPC_FAULT_INVALID_STREAM_TYPE,
                             "Invalid package stream type");

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
    const char *alias;
    RCWorld *world;
    
    g_return_val_if_fail (channel != NULL, NULL);

    value = xmlrpc_struct_new (env);
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_SET_STRING (env, value, "id",
                                  rc_channel_get_id (channel));
    
    RCD_XMLRPC_STRUCT_SET_STRING (env, value, "name",
                                  rc_channel_get_name (channel));

    alias = rc_channel_get_alias (channel);
    RCD_XMLRPC_STRUCT_SET_STRING (env, value, "alias", alias ? alias : "");

    RCD_XMLRPC_STRUCT_SET_INT (env, value, "subscribed",
                               rc_channel_is_subscribed (channel) ? 1 : 0);

    RCD_XMLRPC_STRUCT_SET_STRING (env, value, "description",
                                  rc_channel_get_description (channel));

    RCD_XMLRPC_STRUCT_SET_INT (env, value, "hidden",
                               rc_channel_is_hidden (channel) ? 1 : 0);

    world = rc_channel_get_world (channel);
    
    if (world) {
        GType world_type = G_TYPE_FROM_INSTANCE (world);

        if (g_type_is_a (world_type, RC_TYPE_WORLD_SERVICE)) {
            RCD_XMLRPC_STRUCT_SET_STRING (env, value, "service",
                                          RC_WORLD_SERVICE (world)->unique_id);
        }

        RCD_XMLRPC_STRUCT_SET_INT (env, value, "mounted",
                                   g_type_is_a (world_type,
                                                RC_TYPE_WORLD_LOCAL_DIR)
                                   ? 1 : 0);
    }

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

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

xmlrpc_value *
rcd_rc_resolver_info_to_xmlrpc (RCResolverInfo *info,
                                xmlrpc_env     *env)
{
    xmlrpc_value *value;
    xmlrpc_value *pkg;
    xmlrpc_value *pkg_list;

    g_return_val_if_fail (info != NULL, NULL);

    value = xmlrpc_struct_new (env);
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_SET_STRING (env, value, "type",
                                  rc_resolver_info_type_to_string (rc_resolver_info_type (info)));
    XMLRPC_FAIL_IF_FAULT (env);

    if (info->package) {
        pkg = rcd_rc_package_to_xmlrpc (info->package, env);
        if (pkg == NULL) {
            env->fault_occurred = TRUE; /* probably evil */
            goto cleanup;
        }

        xmlrpc_struct_set_value (env, value, "package", pkg);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_DECREF (pkg);
    }

    RCD_XMLRPC_STRUCT_SET_INT (env, value, "priority", info->priority);
    XMLRPC_FAIL_IF_FAULT (env);
    
    pkg_list = rcd_rc_package_slist_to_xmlrpc_array (info->package_list, env);
    XMLRPC_FAIL_IF_FAULT (env);

    xmlrpc_struct_set_value (env, value, "package_list", pkg_list);
    XMLRPC_FAIL_IF_FAULT (env);

    xmlrpc_DECREF (pkg_list);

    if (info->msg) {
        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "message", info->msg);
    }


    if (info->action) {
        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "action", info->action);
    }

    if (info->trigger) {
        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "trigger", info->trigger);
    }
        
    
    RCD_XMLRPC_STRUCT_SET_INT (env, value, "is_error",
                               rc_resolver_info_is_error (info));

    RCD_XMLRPC_STRUCT_SET_INT (env, value, "is_important",
                               rc_resolver_info_is_important (info));

 cleanup:
    if (env->fault_occurred)
        return NULL;

    return value;
}

struct GetContextInfo {
    xmlrpc_value *info_array;
    xmlrpc_env   *env;
};

static void
get_info_cb (RCResolverInfo *info,
             gpointer        user_data)
{
    struct GetContextInfo *gc = user_data;
    xmlrpc_value *value;
    
    if (gc->env->fault_occurred)
        return;

    value = rcd_rc_resolver_info_to_xmlrpc (info, gc->env);

    xmlrpc_array_append_item (gc->env,
                              gc->info_array,
                              value);

    xmlrpc_DECREF (value);
}

xmlrpc_value *
rcd_rc_resolver_context_info_to_xmlrpc_array (RCResolverContext *context,
                                              RCPackage         *package,
                                              int                priority,
                                              xmlrpc_env        *env)
{
    struct GetContextInfo gc;

    g_return_val_if_fail (context != NULL, NULL);
    g_return_val_if_fail (env != NULL, NULL);

    gc.info_array = xmlrpc_build_value (env, "()");
    XMLRPC_FAIL_IF_FAULT (env);
    gc.env = env;

    rc_resolver_context_foreach_info (context,
                                      package,
                                      priority,
                                      get_info_cb,
                                      &gc);
    
 cleanup:
    if (env->fault_occurred)
        return NULL;

    return gc.info_array;
}


/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

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

xmlrpc_value *
rcd_xmlrpc_package_file_list (RCPackage *package, xmlrpc_env *env)
{
    RCWorld *world;
    RCPackman *packman;
    RCPackageFileSList *files, *iter;
    xmlrpc_value *file_array;

    world = rc_get_world ();
    packman = rc_packman_get_global ();

    files = rc_packman_file_list (packman, package);
    
    file_array = xmlrpc_build_value (env, "()");
    for (iter = files; iter; iter = iter->next) {
        RCPackageFile *file = iter->data;
        xmlrpc_value *file_value;

        file_value = xmlrpc_build_value (env, "s", file->filename);
        xmlrpc_array_append_item (env, file_array, file_value);
        xmlrpc_DECREF (file_value);
    }

    return file_array;
}

static void
copy_array (xmlrpc_env *env, xmlrpc_value **out_array, xmlrpc_value *in_array)
{
    int size, i;

    size = xmlrpc_array_size (env, in_array);
    XMLRPC_FAIL_IF_FAULT (env);

    for (i = 0; i < size; i++) {
        xmlrpc_value *v;

        v = xmlrpc_array_get_item (env, in_array, i);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_array_append_item (env, *out_array, v);
        XMLRPC_FAIL_IF_FAULT (env);
    }

cleanup:
    ;
} /* copy_array */

xmlrpc_value *
rcd_xmlrpc_array_copy (xmlrpc_env *env, int n_params, ...)
{
    va_list args;
    xmlrpc_value *result;
    int i;

    result = xmlrpc_build_value (env, "()");
    if (env->fault_occurred)
        return NULL;

    va_start (args, n_params);
    for (i = 0; i < n_params; i++) {
        copy_array (env, &result, va_arg (args, xmlrpc_value *));
        XMLRPC_FAIL_IF_FAULT (env);
    }

cleanup:
    va_end (args);

    return result;
} /* rcd_xmlrpc_array_copy */
    
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

typedef struct {
    GSList *pending_list;
    gboolean fail_if_any;
    int fault_to_throw;
    xmlrpc_env *env;
    GMainLoop *inferior_loop;
} BlockingInfo;

static gboolean
wait_for_pending_cb (gpointer user_data)
{
    BlockingInfo *info = user_data;
    GSList *iter, *next;
    gboolean exit_out = FALSE;
 
    for (iter = info->pending_list; iter; iter = next) {
        RCPending *pending = RC_PENDING (iter->data);
 
        next = iter->next;

        if (!rc_pending_is_active (pending)) {
            info->pending_list = g_slist_delete_link (info->pending_list, 
                                                      iter);
        }

        if (info->fail_if_any) {
            const char *err_msg = rc_pending_get_error_msg (pending);

            if (err_msg) {
                xmlrpc_env_set_fault (info->env, info->fault_to_throw,
                                      (char *) err_msg);
                exit_out = TRUE;
                break;
            }
        }
    }
 
    if (exit_out || !info->pending_list) {
        g_main_loop_quit (info->inferior_loop);
        return FALSE;
    }
    else
        return TRUE;
}

void
rcd_rpc_block_on_pending_list (xmlrpc_env *env,
                               GSList     *pending_list,
                               gboolean    fail_if_any,
                               int         fault_to_throw)
{
    BlockingInfo info;

    info.pending_list = g_slist_copy (pending_list);
    
    /* Ref the pendings */
    g_slist_foreach (info.pending_list, (GFunc) g_object_ref, NULL);

    info.fail_if_any = fail_if_any;
    info.fault_to_throw = fault_to_throw;
    info.env = env;
    info.inferior_loop = g_main_loop_new (NULL, FALSE);

    g_timeout_add (250, wait_for_pending_cb, &info);
    g_main_loop_run (info.inferior_loop);
    g_main_loop_unref (info.inferior_loop);

    g_slist_foreach (info.pending_list, (GFunc) g_object_unref, NULL);
    g_slist_free (info.pending_list);
}
