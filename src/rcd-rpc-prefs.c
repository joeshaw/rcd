/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-rpc-prefs.c
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
#include "rcd-rpc-prefs.h"

#include "rcd-prefs.h"
#include "rcd-rpc.h"
#include "rcd-rpc-util.h"

typedef xmlrpc_value *(*RCDPrefGetConversionFunc) (xmlrpc_env   *,
                                                   gpointer);
typedef gpointer      (*RCDPrefSetConversionFunc) (xmlrpc_env   *,
                                                   xmlrpc_value *);

static xmlrpc_value *get_string_func  (xmlrpc_env *env, gpointer value);
static xmlrpc_value *get_boolean_func (xmlrpc_env *env, gpointer value);
static xmlrpc_value *get_int_func     (xmlrpc_env *env, gpointer value);

static gpointer      set_string_func  (xmlrpc_env *env, xmlrpc_value *value);
static gpointer      set_boolean_func (xmlrpc_env *env, xmlrpc_value *value);
static gpointer      set_int_func     (xmlrpc_env *env, xmlrpc_value *value);

typedef struct {
    const char               *name;
    const char               *description;
    const char               *category;

    RCDPrefGetConversionFunc  get_conv_func;
    RCDPrefGetFunc            get_pref_func;
    RCDPrivileges             get_privileges;

    RCDPrefSetConversionFunc  set_conv_func;
    RCDPrefSetFunc            set_pref_func;
    RCDPrivileges             set_privileges;
} RCDPrefTable;

static int pref_table_size = 0;
static RCDPrefTable *pref_table = NULL;

/* Functions to convert from a glib value to an xmlrpc value */
static xmlrpc_value *
get_string_func (xmlrpc_env *env, gpointer value)
{
    xmlrpc_value *v = NULL;

    v = xmlrpc_build_value (env, "s", (char *) RC_STRING_TO_XMLRPC (value));

    return v;
} /* get_string_func */

static xmlrpc_value *
get_boolean_func (xmlrpc_env *env, gpointer value)
{
    xmlrpc_value *v = NULL;

    v = xmlrpc_build_value (env, "b", (gboolean) value);

    return v;
} /* get_boolean_func */

static xmlrpc_value *
get_int_func (xmlrpc_env *env, gpointer value)
{
    xmlrpc_value *v = NULL;

    v = xmlrpc_build_value (env, "i", (int) value);
    
    return v;
} /* get_int_func */



/* Functions to convert from xmlrpc values to glib values */
static gpointer
set_string_func (xmlrpc_env *env, xmlrpc_value *value)
{
    char *str;

    xmlrpc_parse_value (env, value, "s", &str);

    return XMLRPC_STRING_TO_RC (str);
} /* set_string_func */

static gpointer
set_boolean_func (xmlrpc_env *env, xmlrpc_value *value)
{
    xmlrpc_bool bool;

    xmlrpc_parse_value (env, value, "b", &bool);

    return (gpointer) bool;
} /* set_boolean_func */

static gpointer
set_int_func (xmlrpc_env *env, xmlrpc_value *value)
{
    xmlrpc_int32 i;

    xmlrpc_parse_value (env, value, "i", &i);
    
    return (gpointer) i;
} /* set_int_func */

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static xmlrpc_value *
get_pref (xmlrpc_env *env, const char *pref_name)
{
    int i;
    xmlrpc_value *result;
    RCDRPCMethodData *method_data;

    method_data = rcd_rpc_get_method_data ();

    for (i = 0; i < pref_table_size; i++) {
        RCDPrefTable pt = pref_table[i];
        gpointer v;

        if (g_strcasecmp (pt.name, pref_name) != 0)
            continue;

        if (!rcd_identity_approve_action (method_data->identity,
                                          pt.get_privileges)) {
            xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PERMISSION_DENIED,
                                  "Permission denied");
            return NULL;
        }
        
        v = pt.get_pref_func ();
        result = pt.get_conv_func (env, v);

        if (env->fault_occurred)
            return NULL;

        return result;
    }

    /* Nothing matched */
    xmlrpc_env_set_fault (env, RCD_RPC_FAULT_INVALID_PREFERENCE,
                          "No preference found");
    return NULL;
} /* get_pref */
	
static xmlrpc_value *
prefs_get_pref (xmlrpc_env   *env,
                xmlrpc_value *param_array,
                void         *user_data)
{
    char *pref_name;
    xmlrpc_value *result = NULL;

    xmlrpc_parse_value (env, param_array, "(s)", &pref_name);
    if (env->fault_occurred)
        return NULL;

    result = get_pref (env, pref_name);

    return result;
} /* prefs_get_pref */

static xmlrpc_value *
prefs_set_pref (xmlrpc_env   *env,
                xmlrpc_value *param_array,
                void         *user_data)
{
    char *pref_name;
    xmlrpc_value *value;
    int i;
    RCDRPCMethodData *method_data;
 
    xmlrpc_parse_value (env, param_array, "(sV)", &pref_name, &value);
    if (env->fault_occurred)
        return NULL;

    method_data = rcd_rpc_get_method_data ();

    for (i = 0; i < pref_table_size; i++) {
        RCDPrefTable pt = pref_table[i];
        gpointer v;

        if (g_strcasecmp (pt.name, pref_name) != 0)
            continue;

        if (!rcd_identity_approve_action (method_data->identity,
                                          pt.set_privileges)) {
            xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PERMISSION_DENIED,
                                  "Permission denied");
            return NULL;
        }

        v = pt.set_conv_func (env, value);
        if (env->fault_occurred)
            return NULL;

        pt.set_pref_func (v);

        return xmlrpc_build_value (env, "i", 0);
    }

    /* Nothing matched */
    xmlrpc_env_set_fault (env, RCD_RPC_FAULT_INVALID_PREFERENCE,
                          "No preference found");
    return NULL;
} /* prefs_set_pref */

static xmlrpc_value *
prefs_list_prefs (xmlrpc_env   *env,
                  xmlrpc_value *param_array,
                  void         *user_data)
{
    int i;
    xmlrpc_value *result = NULL;
    gboolean any_valid = FALSE;

    result = xmlrpc_build_value (env, "()");
    XMLRPC_FAIL_IF_FAULT (env);

    for (i = 0; i < pref_table_size; i++) {
        RCDPrefTable pt = pref_table[i];
        xmlrpc_value *pref_info;
        xmlrpc_value *value;
        xmlrpc_value *member;

        value = get_pref (env, pt.name);

        /*
         * This will filter out preferences that we don't have privileges
         * to view.
         */
        if (env->fault_occurred &&
            env->fault_code == RCD_RPC_FAULT_PERMISSION_DENIED) {
            xmlrpc_env_clean (env);
            xmlrpc_env_init (env);
            continue;
        }
        else
            any_valid = TRUE;
            
        pref_info = xmlrpc_struct_new (env);

        RCD_XMLRPC_STRUCT_SET_STRING (env, pref_info, "name", pt.name);
        XMLRPC_FAIL_IF_FAULT (env);

        RCD_XMLRPC_STRUCT_SET_STRING (env, pref_info, "description",
                                      pt.description);
        XMLRPC_FAIL_IF_FAULT (env);

        if (pt.category) {
            RCD_XMLRPC_STRUCT_SET_STRING (env, pref_info, "category",
                                          pt.category);
            XMLRPC_FAIL_IF_FAULT (env);
        }

        member = xmlrpc_build_value (env, "V", value);
        XMLRPC_FAIL_IF_FAULT (env);
        xmlrpc_DECREF (value);

        xmlrpc_struct_set_value (env, pref_info, "value", member);

        xmlrpc_DECREF (member);

        xmlrpc_array_append_item (env, result, pref_info);

        xmlrpc_DECREF (pref_info);
    }

    if (!any_valid && pref_table_size) {
        xmlrpc_DECREF (result);
        result = NULL;
        xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PERMISSION_DENIED,
                              "Permission denied");
    }

cleanup:
    return result;
} /* prefs_list_prefs */

static void
rcd_rpc_prefs_register_pref_full (const char               *pref_name,
                                  const char               *description,
                                  const char               *category,
                                  RCDPrefGetConversionFunc  get_conv_func,
                                  RCDPrefGetFunc            get_pref_func,
                                  const char               *get_privileges_str,
                                  RCDPrefSetConversionFunc  set_conv_func,
                                  RCDPrefSetFunc            set_pref_func,
                                  const char               *set_privileges_str)
{
    pref_table_size++;

    if (!pref_table)
        pref_table = g_malloc (sizeof (RCDPrefTable) * pref_table_size);
    else
        pref_table = g_realloc (pref_table,
                                sizeof (RCDPrefTable) * pref_table_size);

    if (get_privileges_str == NULL)
        get_privileges_str = "";

    if (set_privileges_str == NULL)
        set_privileges_str = "";

    pref_table[pref_table_size - 1].name = pref_name;
    pref_table[pref_table_size - 1].description = description;
    pref_table[pref_table_size - 1].category = category;
    pref_table[pref_table_size - 1].get_conv_func = get_conv_func;
    pref_table[pref_table_size - 1].get_pref_func = get_pref_func;
    pref_table[pref_table_size - 1].get_privileges =
        rcd_privileges_from_string (get_privileges_str);
    pref_table[pref_table_size - 1].set_conv_func = set_conv_func;
    pref_table[pref_table_size - 1].set_pref_func = set_pref_func;
    pref_table[pref_table_size - 1].set_privileges =
        rcd_privileges_from_string (set_privileges_str);
} /* rcd_rpc_prefs_register_pref_full */

void
rcd_rpc_prefs_register_pref (const char     *pref_name,
                             RCDPrefType     pref_type,
                             const char     *description,
                             const char     *category,
                             RCDPrefGetFunc  get_pref_func,
                             const char     *get_privileges_str,
                             RCDPrefSetFunc  set_pref_func,
                             const char     *set_privileges_str)
{
    /* Make sure to keep these in sync with RCDPrefType! */
    RCDPrefGetConversionFunc get_conv_funcs[] = {
        get_string_func,
        get_boolean_func,
        get_int_func
    };

    RCDPrefSetConversionFunc set_conv_funcs[] = {
        set_string_func,
        set_boolean_func,
        set_int_func
    };

    rcd_rpc_prefs_register_pref_full (
        pref_name, description, category,
        get_conv_funcs[pref_type], get_pref_func, get_privileges_str,
        set_conv_funcs[pref_type], set_pref_func, set_privileges_str);
} /* rcd_rpc_prefs_register_pref */

void
rcd_rpc_prefs_register_methods (void)
{
    RCWorld *world;
    RCPackman *packman;

    rcd_rpc_prefs_register_pref (
        "host", RCD_PREF_STRING,
        "Server URL",
        "Server",
        (RCDPrefGetFunc) rcd_prefs_get_host, "view",
        (RCDPrefSetFunc) rcd_prefs_set_host, "superuser");

    rcd_rpc_prefs_register_pref (
        "enable-premium", RCD_PREF_BOOLEAN,
        "Enable Premium Services (Red Carpet Express, CorporateConnect, or Enterprise)",
        "Server",
        (RCDPrefGetFunc) rcd_prefs_get_premium, "view",
        (RCDPrefSetFunc) rcd_prefs_set_premium, "superuser");

    rcd_rpc_prefs_register_pref (
        "proxy-url", RCD_PREF_STRING,
        "Proxy URL",
        "Proxy",
        (RCDPrefGetFunc) rcd_prefs_get_proxy_url, "superuser",
        (RCDPrefSetFunc) rcd_prefs_set_proxy_url, "superuser");

    rcd_rpc_prefs_register_pref (
        "proxy-username", RCD_PREF_STRING,
        "Proxy username",
        "Proxy",
        (RCDPrefGetFunc) rcd_prefs_get_proxy_username, "superuser",
        (RCDPrefSetFunc) rcd_prefs_set_proxy_username, "superuser");

    rcd_rpc_prefs_register_pref (
        "proxy-password", RCD_PREF_STRING,
        "Proxy password",
        "Proxy",
        (RCDPrefGetFunc) rcd_prefs_get_proxy_password, "superuser",
        (RCDPrefSetFunc) rcd_prefs_set_proxy_password, "superuser");

    rcd_rpc_prefs_register_pref (
        "http-1.0", RCD_PREF_BOOLEAN,
        "Use HTTP/1.0 for server communications",
        "Server",
        (RCDPrefGetFunc) rcd_prefs_get_http10_enabled, "view",
        (RCDPrefSetFunc) rcd_prefs_set_http10_enabled, "superuser");

    rcd_rpc_prefs_register_pref (
        "require-verified-certificates", RCD_PREF_BOOLEAN,
        "Verify server SSL certificates",
        "Server",
        (RCDPrefGetFunc) rcd_prefs_get_require_verified_certificates, "superuser",
        (RCDPrefSetFunc) rcd_prefs_set_require_verified_certificates, "superuser");

    rcd_rpc_prefs_register_pref (
        "cache-enabled", RCD_PREF_BOOLEAN,
        "Cache downloaded packages and metadata",
        "Cache",
        (RCDPrefGetFunc) rcd_prefs_get_cache_enabled, "view",
        (RCDPrefSetFunc) rcd_prefs_set_cache_enabled, "superuser");

    rcd_rpc_prefs_register_pref (
        "cache-directory", RCD_PREF_STRING,
        "The directory to store cached packages and metadata",
        "Cache",
        (RCDPrefGetFunc) rcd_prefs_get_cache_dir, "view",
        (RCDPrefSetFunc) rcd_prefs_set_cache_dir, "superuser");

    rcd_rpc_prefs_register_pref (
        "cache-cleanup-enabled", RCD_PREF_BOOLEAN,
        "Automatically clean up the cache",
        "Cache",
        (RCDPrefGetFunc) rcd_prefs_get_cache_cleanup_enabled, "view",
        (RCDPrefSetFunc) rcd_prefs_set_cache_cleanup_enabled, "superuser");

    rcd_rpc_prefs_register_pref (
        "cache-max-age-in-days", RCD_PREF_INT,
        "The number of days a package may be in the cache before clean up",
        "Cache",
        (RCDPrefGetFunc) rcd_prefs_get_cache_max_age_in_days, "view",
        (RCDPrefSetFunc) rcd_prefs_set_cache_max_age_in_days, "superuser");

    rcd_rpc_prefs_register_pref (
        "cache-max-size-in-mb", RCD_PREF_INT,
        "The maximum size of the cache (in mb)",
        "Cache",
        (RCDPrefGetFunc) rcd_prefs_get_cache_max_size_in_mb, "view",
        (RCDPrefSetFunc) rcd_prefs_set_cache_max_size_in_mb, "superuser");

    rcd_rpc_prefs_register_pref (
        "require-signatures", RCD_PREF_BOOLEAN,
        "Require packages be cryptographically signed before installing",
        "Advanced",
        (RCDPrefGetFunc) rcd_prefs_get_require_signed_packages, "view",
        (RCDPrefSetFunc) rcd_prefs_set_require_signed_packages, "superuser");

    rcd_rpc_prefs_register_pref (
        "heartbeat-interval", RCD_PREF_INT,
        "The interval between refreshing server data (in seconds)",
        "Advanced",
        (RCDPrefGetFunc) rcd_prefs_get_heartbeat_interval, "view",
        (RCDPrefSetFunc) rcd_prefs_set_heartbeat_interval, "superuser");

    rcd_rpc_prefs_register_pref (
        "max-downloads", RCD_PREF_INT,
        "Maximum number of concurrent package downloads",
        "Advanced",
        (RCDPrefGetFunc) rcd_prefs_get_max_downloads, "view",
        (RCDPrefSetFunc) rcd_prefs_set_max_downloads, "superuser");

    rcd_rpc_prefs_register_pref (
        "debug-level", RCD_PREF_INT,
        "Level at which to log to standard error (0 to 6)",
        "Advanced",
        (RCDPrefGetFunc) rcd_prefs_get_debug_level, "view",
        (RCDPrefSetFunc) rcd_prefs_set_debug_level, "superuser");

    rcd_rpc_prefs_register_pref (
        "syslog-level", RCD_PREF_INT,
        "Level at which to log to syslog (0 to 6)",
        "Advanced",
        (RCDPrefGetFunc) rcd_prefs_get_syslog_level, "view",
        (RCDPrefSetFunc) rcd_prefs_set_syslog_level, "superuser");

    world = rc_get_world ();
    packman = rc_world_get_packman (world);
    if (rc_packman_get_capabilities (packman) & RC_PACKMAN_CAP_REPACKAGING) {
        rcd_rpc_prefs_register_pref (
            "repackage", RCD_PREF_BOOLEAN,
            "Repackage old software on upgrade or removal, allowing undo/rollback",
            "Advanced",
            (RCDPrefGetFunc) rcd_prefs_get_repackage, "view",
            (RCDPrefSetFunc) rcd_prefs_set_repackage, "superuser");
    }

    /* We handle more fine grained privileges in these pref functions. */
    rcd_rpc_register_method ("rcd.prefs.get_pref",
                             prefs_get_pref,
                             NULL,
                             NULL);

    rcd_rpc_register_method ("rcd.prefs.set_pref",
                             prefs_set_pref,
                             NULL,
                             NULL);

    rcd_rpc_register_method ("rcd.prefs.list_prefs",
                             prefs_list_prefs,
                             NULL,
                             NULL);
} /* rcd_rpc_prefs_register_methods */

