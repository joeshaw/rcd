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

static xmlrpc_value *get_string_func  (xmlrpc_env *env, gpointer value);
static xmlrpc_value *get_boolean_func (xmlrpc_env *env, gpointer value);
static xmlrpc_value *get_int_func     (xmlrpc_env *env, gpointer value);

static gpointer      set_string_func  (xmlrpc_env *env, xmlrpc_value *value);
static gpointer      set_boolean_func (xmlrpc_env *env, xmlrpc_value *value);
static gpointer      set_int_func     (xmlrpc_env *env, xmlrpc_value *value);

typedef struct {
    const char               *name;

    RCDPrefGetConversionFunc  get_conv_func;
    RCDPrefGetFunc            get_pref_func;

    RCDPrefSetConversionFunc  set_conv_func;
    RCDPrefSetFunc            set_pref_func;
} RCDPrefTable;

static int pref_table_size = 0;
static RCDPrefTable *pref_table = NULL;

/* Functions to convert from a glib value to an xmlrpc value */
static xmlrpc_value *
get_string_func (xmlrpc_env *env, gpointer value)
{
    xmlrpc_value *v = NULL;

    v = xmlrpc_build_value (env, "s", (char *) value);

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

    return str;
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

    for (i = 0; i < pref_table_size; i++) {
        RCDPrefTable pt = pref_table[i];
        gpointer v;

        if (g_strcasecmp (pt.name, pref_name) != 0)
            continue;

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
 
    xmlrpc_parse_value (env, param_array, "(sV)", &pref_name, &value);
    if (env->fault_occurred)
        return NULL;

    for (i = 0; i < pref_table_size; i++) {
        RCDPrefTable pt = pref_table[i];
        gpointer v;

        if (g_strcasecmp (pt.name, pref_name) != 0)
            continue;

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

    result = xmlrpc_build_value (env, "()");
    XMLRPC_FAIL_IF_FAULT (env);

    for (i = 0; i < pref_table_size; i++) {
        RCDPrefTable pt = pref_table[i];
        xmlrpc_value *pref_info;
        xmlrpc_value *value;
        xmlrpc_value *member;

        pref_info = xmlrpc_struct_new (env);

        RCD_XMLRPC_STRUCT_SET_STRING (env, pref_info, "name", pt.name);
        XMLRPC_FAIL_IF_FAULT (env);

        value = get_pref (env, pt.name);
        g_assert (value && !env->fault_occurred);

        member = xmlrpc_build_value (env, "V", value);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_DECREF (value);

        xmlrpc_struct_set_value (env, pref_info, "value", member);

        xmlrpc_DECREF (member);

        xmlrpc_array_append_item (env, result, pref_info);

        xmlrpc_DECREF (pref_info);
    }

cleanup:
    return result;
} /* prefs_list_prefs */

void
rcd_rpc_prefs_register_pref_full (const char  *pref_name,
                                  RCDPrefGetConversionFunc get_conv_func,
                                  RCDPrefGetFunc           get_pref_func,
                                  RCDPrefSetConversionFunc set_conv_func,
                                  RCDPrefSetFunc           set_pref_func)
{
    pref_table_size++;

    if (!pref_table)
        pref_table = g_malloc (sizeof (RCDPrefTable) * pref_table_size);
    else
        pref_table = g_realloc (pref_table,
                                sizeof (RCDPrefTable) * pref_table_size);

    pref_table[pref_table_size - 1].name = pref_name;
    pref_table[pref_table_size - 1].get_conv_func = get_conv_func;
    pref_table[pref_table_size - 1].get_pref_func = get_pref_func;
    pref_table[pref_table_size - 1].set_conv_func = set_conv_func;
    pref_table[pref_table_size - 1].set_pref_func = set_pref_func;
} /* rcd_rpc_prefs_register_pref_full */

void
rcd_rpc_prefs_register_pref (const char     *pref_name,
                             RCDPrefType     pref_type,
                             RCDPrefGetFunc  get_pref_func,
                             RCDPrefSetFunc  set_pref_func)
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
        pref_name,
        get_conv_funcs[pref_type], get_pref_func,
        set_conv_funcs[pref_type], set_pref_func);
} /* rcd_rpc_prefs_register_pref */

void
rcd_rpc_prefs_register_methods(void)
{
    rcd_rpc_prefs_register_pref (
        "cache-directory", RCD_PREF_STRING,
        (RCDPrefGetFunc) rcd_prefs_get_cache_dir,
        (RCDPrefSetFunc) rcd_prefs_set_cache_dir);

    rcd_rpc_prefs_register_pref (
        "cache-enabled", RCD_PREF_BOOLEAN,
        (RCDPrefGetFunc) rcd_prefs_get_cache_enabled,
        (RCDPrefSetFunc) rcd_prefs_set_cache_enabled);

    rcd_rpc_prefs_register_pref (
        "http-1.0", RCD_PREF_BOOLEAN,
        (RCDPrefGetFunc) rcd_prefs_get_http10_enabled,
        (RCDPrefSetFunc) rcd_prefs_set_http10_enabled);

    rcd_rpc_prefs_register_pref (
        "heartbeat-interval", RCD_PREF_INT,
        (RCDPrefGetFunc) rcd_prefs_get_heartbeat_interval,
        (RCDPrefSetFunc) rcd_prefs_set_heartbeat_interval);

    rcd_rpc_prefs_register_pref (
        "max-downloads", RCD_PREF_INT,
        (RCDPrefGetFunc) rcd_prefs_get_max_downloads,
        (RCDPrefSetFunc) rcd_prefs_set_max_downloads);

    rcd_rpc_prefs_register_pref (
        "debug-level", RCD_PREF_INT,
        (RCDPrefGetFunc) rcd_prefs_get_debug_level,
        (RCDPrefSetFunc) rcd_prefs_set_debug_level);

    rcd_rpc_prefs_register_pref (
        "syslog-level", RCD_PREF_INT,
        (RCDPrefGetFunc) rcd_prefs_get_syslog_level,
        (RCDPrefSetFunc) rcd_prefs_set_syslog_level);

    rcd_rpc_register_method ("rcd.prefs.get_pref",
                             prefs_get_pref,
                             "view",
                             NULL);

    rcd_rpc_register_method ("rcd.prefs.set_pref",
                             prefs_set_pref,
                             "superuser",
                             NULL);

    rcd_rpc_register_method ("rcd.prefs.list_prefs",
                             prefs_list_prefs,
                             "view",
                             NULL);
} /* rcd_rpc_prefs_register_methods */

