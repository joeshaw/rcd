/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-mirror.h
 *
 * Copyright (C) 2003 Ximian, Inc.
 *
 */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
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
#include "rcd-rpc-mirror.h"

#include "rcd-rpc.h"
#include "rcd-rpc-util.h"
#include "rcd-mirror.h"

xmlrpc_value *
rcd_mirror_to_xmlrpc (RCDMirror  *mirror,
                      xmlrpc_env *env)
{
    xmlrpc_value *value;
    g_return_val_if_fail (mirror != NULL, NULL);

    value = xmlrpc_struct_new (env);
    XMLRPC_FAIL_IF_FAULT (env);

    if (mirror->name && *mirror->name)
        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "name",
                                      mirror->name);

    if (mirror->location && *mirror->location)
        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "location",
                                      mirror->location);

    if (mirror->url && *mirror->url)
        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "url",
                                      mirror->url);

    if (mirror->ftp && *mirror->ftp)
        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "ftp",
                                      mirror->ftp);

    if (mirror->contact && *mirror->contact)
        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "contact",
                                      mirror->contact);

 cleanup:
    if (env->fault_occurred) {
        if (value)
            xmlrpc_DECREF (value);
        return NULL;
    }

    return value;
}

struct GetAllInfo {
    xmlrpc_value *array;
    xmlrpc_env   *env;
    gboolean      failed;
};

static void
add_mirror_cb (RCDMirror *mirror, gpointer user_data)
{
    struct GetAllInfo *info = user_data;
    xmlrpc_value *mirror_value;

    if (info->failed)
        return;

    mirror_value = rcd_mirror_to_xmlrpc (mirror, info->env);
    if (mirror_value) {
        xmlrpc_array_append_item (info->env, info->array, mirror_value);
        xmlrpc_DECREF (mirror_value);
        return;
    }

    /* Fall through on error */
    info->failed = TRUE;
}

static xmlrpc_value *
mirror_get_all (xmlrpc_env   *env,
                xmlrpc_value *param_array,
                void         *user_data)
{
    struct GetAllInfo info;

    info.env = env;
    info.array = xmlrpc_build_value (env, "()");
    info.failed = FALSE;

#if 0
    /* FIXME */
    rcd_mirror_foreach (add_mirror_cb, &info);
#endif

    if (info.failed || env->fault_occurred)
        return NULL;

    return info.array;
}

void
rcd_rpc_mirror_register_methods (void)
{
    rcd_rpc_register_method ("rcd.mirror.get_all",
                             mirror_get_all,
                             "view",
                             NULL);
}

