/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-rpc-license.c
 *
 * Copyright (C) 2003 Ximian, Inc.
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
#include "rcd-rpc-license.h"

#include <libredcarpet.h>
#include <xmlrpc.h>

#include "rcd-license.h"
#include "rcd-rpc.h"
#include "rcd-rpc-util.h"

static xmlrpc_value *
license_lookup (xmlrpc_env   *env,
                xmlrpc_value *param_array,
                void         *user_data)
{
    xmlrpc_value *license_names;
    xmlrpc_value *license_texts = NULL;
    int size;
    int i;

    xmlrpc_parse_value (env, param_array, "(A)", &license_names);
    XMLRPC_FAIL_IF_FAULT (env);

    size = xmlrpc_array_size (env, license_names);
    XMLRPC_FAIL_IF_FAULT (env);

    license_texts = xmlrpc_build_value (env, "()");
    XMLRPC_FAIL_IF_FAULT (env);

    for (i = 0; i < size; i++) {
        xmlrpc_value *xmlrpc_name;
        xmlrpc_value *xmlrpc_text;
        const char *name;
        const char *text;

        xmlrpc_name = xmlrpc_array_get_item (env, license_names, i);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_parse_value (env, xmlrpc_name, "s", &name);
        XMLRPC_FAIL_IF_FAULT (env);

        text = rcd_license_lookup (name);

        if (!text) {
            xmlrpc_env_set_fault_formatted (env,
                                            RCD_RPC_FAULT_LICENSE_NOT_FOUND,
                                            "License '%s' not found", name);
            goto cleanup;
        }

        xmlrpc_text = xmlrpc_build_value (env, "s", text);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_array_append_item (env, license_texts, xmlrpc_text);
        XMLRPC_FAIL_IF_FAULT (env);
        xmlrpc_DECREF (xmlrpc_text);
    }

cleanup:
    if (env->fault_occurred)
        return NULL;

    return license_texts;
}

static xmlrpc_value *
license_lookup_from_packages (xmlrpc_env   *env,
                              xmlrpc_value *param_array,
                              void         *user_data)
{
    xmlrpc_value *xmlrpc_packages;
    RCPackageSList *packages = NULL;
    GSList *licenses = NULL;
    xmlrpc_value *license_texts = NULL;
    GSList *iter;

    xmlrpc_parse_value (env, param_array, "(A)", &xmlrpc_packages);
    XMLRPC_FAIL_IF_FAULT (env);

    packages = rcd_xmlrpc_array_to_rc_package_slist (xmlrpc_packages, env,
                                                     RCD_PACKAGE_FROM_XMLRPC_PACKAGE);
    XMLRPC_FAIL_IF_FAULT (env);

    licenses = rcd_license_lookup_from_package_slist (packages);

    license_texts = xmlrpc_build_value (env, "()");
    XMLRPC_FAIL_IF_FAULT (env);

    for (iter = licenses; iter; iter = iter->next) {
        xmlrpc_value *xmlrpc_text;

        xmlrpc_text = xmlrpc_build_value (env, "s", (char *) iter->data);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_array_append_item (env, license_texts, xmlrpc_text);
        XMLRPC_FAIL_IF_FAULT (env);
        xmlrpc_DECREF (xmlrpc_text);
    }

cleanup:

    if (packages) {
        rc_package_slist_unref (packages);
        g_slist_free (packages);
    }

    g_slist_free (licenses);

    if (env->fault_occurred)
        return NULL;

    return license_texts;
}

void
rcd_rpc_license_register_methods(void)
{
    rcd_rpc_register_method ("rcd.license.lookup",
                             license_lookup,
                             NULL, NULL);
    rcd_rpc_register_method ("rcd.license.lookup_from_packages",
                             license_lookup_from_packages,
                             NULL, NULL);
} /* rcd_rpc_license_register_methods */

