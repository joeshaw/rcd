/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-rpc-news.c
 *
 * Copyright (C) 2002 Ximian, Inc.
 *
 * Developed by Jon Trowbridge <trow@ximian.com>
 */

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
#include "rcd-rpc-news.h"

#include "rcd-rpc.h"
#include "rcd-rpc-util.h"
#include "rcd-news.h"

xmlrpc_value *
rcd_news_to_xmlrpc (RCDNews    *news,
                    xmlrpc_env *env)
{
    xmlrpc_value *value;
    char *time_str, *c;

    g_return_val_if_fail (news != NULL, NULL);

    value = xmlrpc_struct_new (env);
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_SET_STRING (env, value, "title",
                                  news->title ? news->title : "");

    RCD_XMLRPC_STRUCT_SET_STRING (env, value, "url",
                                  news->url ? news->url : "");

    RCD_XMLRPC_STRUCT_SET_STRING (env, value, "icon_url",
                                  news->icon_url ? news->icon_url : "");

    RCD_XMLRPC_STRUCT_SET_STRING (env, value, "summary",
                                  news->summary ? news->summary : "");

    RCD_XMLRPC_STRUCT_SET_STRING (env, value, "channel_name",
                                  news->channel_name ? news->channel_name : "");

    RCD_XMLRPC_STRUCT_SET_INT (env, value, "timestamp",
                               news->timestamp);

    time_str = ctime (&news->timestamp);
    for (c = time_str; *c; ++c) {
        if (*c == '\n') {
            *c = '\0';
            break;
        }
    }

    RCD_XMLRPC_STRUCT_SET_STRING (env, value, "time_str",
                                  time_str);

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
add_news_cb (RCDNews *news, gpointer user_data)
{
    struct GetAllInfo *info = user_data;
    xmlrpc_value *news_value;

    if (info->failed)
        return;

    news_value = rcd_news_to_xmlrpc (news, info->env);
    if (news_value) {
        xmlrpc_array_append_item (info->env, info->array, news_value);
        xmlrpc_DECREF (news_value);
        return;
    }

    /* fall through on error */
    info->failed = TRUE;
}

static xmlrpc_value *
news_get_all (xmlrpc_env   *env,
              xmlrpc_value *param_array,
              void         *user_data)
{
    struct GetAllInfo info;

    info.env    = env;
    info.array  = xmlrpc_build_value (env, "()");
    info.failed = FALSE;

    rcd_news_foreach (add_news_cb, &info);

    if (info.failed || env->fault_occurred)
        return NULL;

    return info.array;
}

void
rcd_rpc_news_register_methods (void)
{
    rcd_rpc_register_method ("rcd.news.get_all",
                             news_get_all,
                             rcd_auth_action_list_from_1 (RCD_AUTH_VIEW),
                             NULL);
}
