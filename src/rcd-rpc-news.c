/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-rpc-news.c
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
#include "rcd-rpc-news.h"

#include "rcd-news.h"
#include "rcd-rpc.h"
#include "rcd-rpc-util.h"
#include "rcd-world-remote.h"

xmlrpc_value *
rcd_news_to_xmlrpc (RCDNews        *news,
                    RCDWorldRemote *remote,
                    xmlrpc_env     *env)
{
    xmlrpc_value *value;
    char *time_str, *c;

    g_return_val_if_fail (news != NULL, NULL);

    value = xmlrpc_struct_new (env);
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_SET_STRING (env, value, "server",
                                  RC_WORLD_SERVICE (remote)->name);

    RCD_XMLRPC_STRUCT_SET_STRING (env, value, "title", news->title);

    RCD_XMLRPC_STRUCT_SET_STRING (env, value, "url", news->url);

    RCD_XMLRPC_STRUCT_SET_STRING (env, value, "icon_url", news->icon_url);

    RCD_XMLRPC_STRUCT_SET_STRING (env, value, "summary", news->summary);

    RCD_XMLRPC_STRUCT_SET_STRING (env, value, "channel_name",
                                  news->channel_name);

    RCD_XMLRPC_STRUCT_SET_INT (env, value, "timestamp", news->timestamp);

    time_str = ctime (&news->timestamp);
    for (c = time_str; *c; ++c) {
        if (*c == '\n') {
            *c = '\0';
            break;
        }
    }

    RCD_XMLRPC_STRUCT_SET_STRING (env, value, "time_str", time_str);
    
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

    RCDWorldRemote *remote;
};

static void
add_news_cb (RCDNews *news, gpointer user_data)
{
    struct GetAllInfo *info = user_data;
    xmlrpc_value *news_value;

    if (info->failed)
        return;

    news_value = rcd_news_to_xmlrpc (news, info->remote, info->env);
    if (news_value) {
        xmlrpc_array_append_item (info->env, info->array, news_value);
        xmlrpc_DECREF (news_value);
        return;
    }

    /* fall through on error */
    info->failed = TRUE;
}

static gboolean
foreach_subworld_cb (RCWorld *world, gpointer user_data)
{
    struct GetAllInfo *info = user_data;

    /* News is only on RCDWorldRemote objects */
    if (!g_type_is_a (G_TYPE_FROM_INSTANCE (world), RCD_TYPE_WORLD_REMOTE))
        return TRUE;

    info->remote = RCD_WORLD_REMOTE (world);

    rcd_world_remote_foreach_news (info->remote, add_news_cb, info);

    return TRUE;
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

    rc_world_multi_foreach_subworld (RC_WORLD_MULTI (rc_get_world ()),
                                     foreach_subworld_cb, &info);

    if (info.failed || env->fault_occurred)
        return NULL;

    return info.array;
}

void
rcd_rpc_news_register_methods (void)
{
    rcd_rpc_register_method ("rcd.news.get_all",
                             news_get_all,
                             "view",
                             NULL);
}
