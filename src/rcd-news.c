/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-news.c
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
#include "rcd-news.h"

#include <stdlib.h>

#include <xml-util.h>

RCDNews *
rcd_news_parse (xmlNode *node)
{
    RCDNews *news;

    g_return_val_if_fail (node != NULL, NULL);

    if (g_strcasecmp (node->name, "item"))
        return NULL;

    news = g_new0 (RCDNews, 1);

    node = node->xmlChildrenNode;
    while (node != NULL) {

        if (! g_strcasecmp (node->name, "title")) {
            news->title = xml_get_content (node);
        } else if (! g_strcasecmp (node->name, "link")) {
            news->url = xml_get_content (node);
        } else if (! g_strcasecmp (node->name, "icon")) {
            news->icon_url = xml_get_content (node);
        } else if (! g_strcasecmp (node->name, "summary")) {
            news->summary = xml_get_content (node);
        } else if (! g_strcasecmp (node->name, "channel")) {
            news->channel_name = xml_get_content (node);
        } else if (! g_strcasecmp (node->name, "date")) {
            char *str = xml_get_content (node);
            news->timestamp = (time_t) atol (str);
            g_free (str);
        } else {
            /* Do nothing */
        }
        
        node = node->next;
    }
    
    return news;
}

void
rcd_news_free (RCDNews *news)
{
    if (news != NULL) {
        g_free (news->title);
        g_free (news->url);
        g_free (news->icon_url);
        g_free (news->summary);
        g_free (news->channel_name);
        g_free (news);
    }
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static GSList *news_slist = NULL;

void
rcd_news_add (RCDNews *news)
{
    g_return_if_fail (news != NULL);
    news_slist = g_slist_append (news_slist, news);
}

void
rcd_news_clear (void)
{
    GSList *iter;

    for (iter = news_slist; iter != NULL; iter = iter->next) {
        RCDNews *news = iter->data;
        rcd_news_free (news);
        g_slist_free (news_slist);
    }
    news_slist = NULL;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

void
rcd_news_foreach (RCDNewsFn fn, gpointer user_data)
{
    GSList *iter;
    g_return_if_fail (fn != NULL);

    for (iter = news_slist; iter != NULL; iter = iter->next) {
        fn ((RCDNews *) iter->data, user_data);
    }
    
}
