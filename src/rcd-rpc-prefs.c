/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-rpc-prefs.c
 *
 * Copyright (C) 2002 Ximian, Inc.
 *
 */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License, version 2,
 * as published by the Free Software Foundation.
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

#include <xmlrpc.h>

#include "rcd-prefs.h"
#include "rcd-rpc.h"
#include "rcd-rpc-util.h"

static xmlrpc_value *get_string_func  (xmlrpc_env *env, gpointer value);
static xmlrpc_value *get_boolean_func (xmlrpc_env *env, gpointer value);
static xmlrpc_value *get_int_func     (xmlrpc_env *env, gpointer value);

static gpointer      set_string_func  (xmlrpc_env *env, xmlrpc_value *value);
static gpointer      set_boolean_func (xmlrpc_env *env, xmlrpc_value *value);
static gpointer      set_int_func     (xmlrpc_env *env, xmlrpc_value *value);

typedef xmlrpc_value *(*PrefGetConversionFunc) (xmlrpc_env   *env,
                                                gpointer      value);
typedef gpointer      (*PrefSetConversionFunc) (xmlrpc_env   *env, 
                                                xmlrpc_value *value);

typedef gpointer      (*PrefGetFunc) (void);
typedef void          (*PrefSetFunc) (gpointer);

typedef struct {
    const char            *name;

    PrefGetConversionFunc  get_conv_func;
    PrefGetFunc            get_pref_func;

    PrefSetConversionFunc  set_conv_func;
    PrefSetFunc            set_pref_func;
} RPCPrefTable;

static RPCPrefTable pref_table[] = {
    { "cache-directory",
      get_string_func,  (PrefGetFunc) rcd_prefs_get_cache_dir,
      set_string_func,  (PrefSetFunc) rcd_prefs_set_cache_dir },

    { "cache-enabled",
      get_boolean_func, (PrefGetFunc) rcd_prefs_get_cache_enabled,
      set_boolean_func, (PrefSetFunc) rcd_prefs_set_cache_enabled },

    { "http-1.0",
      get_boolean_func, (PrefGetFunc) rcd_prefs_get_http10_enabled,
      set_boolean_func, (PrefSetFunc) rcd_prefs_set_http10_enabled },

    { "heartbeat-interval",
      get_int_func,     (PrefGetFunc) rcd_prefs_get_heartbeat_interval,
      set_int_func,     (PrefSetFunc) rcd_prefs_set_heartbeat_interval },

    { 0 },
};

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

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
get_pref (xmlrpc_env *env,
          const char *pref_name)
{
    RPCPrefTable *p;
    xmlrpc_value *result;

    for (p = pref_table; p->name; p++) {
        gpointer v;

        if (g_strcasecmp (p->name, pref_name) != 0)
            continue;

        v = p->get_pref_func ();
        result = p->get_conv_func (env, v);

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
    RPCPrefTable *p;
 
    xmlrpc_parse_value (env, param_array, "(sV)", &pref_name, &value);
    if (env->fault_occurred)
        return NULL;

    for (p = pref_table; p->name; p++) {
        gpointer v;

        if (g_strcasecmp (p->name, pref_name) != 0)
            continue;

        v = p->set_conv_func (env, value);
        if (env->fault_occurred)
            return NULL;

        p->set_pref_func (v);

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
    RPCPrefTable *p;
    xmlrpc_value *result = NULL;

    result = xmlrpc_build_value (env, "()");
    XMLRPC_FAIL_IF_FAULT (env);

    for (p = pref_table; p->name; p++) {
        xmlrpc_value *pref_info;
        xmlrpc_value *value;
        xmlrpc_value *member;

        pref_info = xmlrpc_struct_new (env);

        RCD_XMLRPC_STRUCT_SET_STRING (env, pref_info, "name", p->name);
        XMLRPC_FAIL_IF_FAULT (env);

        value = get_pref (env, p->name);
        g_assert (value && !env->fault_occurred);

        member = xmlrpc_build_value (env, "V", value);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_struct_set_value (env, pref_info, "value", member);

        xmlrpc_DECREF (member);

        xmlrpc_array_append_item (env, result, pref_info);

        xmlrpc_DECREF (pref_info);
    }

cleanup:
    return result;
} /* prefs_list_prefs */

void
rcd_rpc_prefs_register_methods(void)
{
    rcd_rpc_register_method ("rcd.prefs.get_pref",
                             prefs_get_pref,
                             rcd_auth_action_list_from_1 (RCD_AUTH_VIEW), 
                             NULL);

    rcd_rpc_register_method ("rcd.prefs.set_pref",
                             prefs_set_pref,
                             /* FIXME: probably the wrong auth to use here */
                             rcd_auth_action_list_from_1 (RCD_AUTH_SUPERUSER),
                             NULL);

    rcd_rpc_register_method ("rcd.prefs.list_prefs",
                             prefs_list_prefs,
                             rcd_auth_action_list_from_1 (RCD_AUTH_VIEW),
                             NULL);
} /* rcd_rpc_prefs_register_methods */

