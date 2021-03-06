/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-news.h
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

#ifndef __RCD_NEWS_H__
#define __RCD_NEWS_H__

#include <glib.h>
#include <libxml/tree.h>

#include <time.h>

typedef struct _RCDNews RCDNews;

typedef void (*RCDNewsFn) (RCDNews *, gpointer user_data);

struct _RCDNews {
    char  *title;
    char  *url;
    char  *icon_url;
    char  *summary;
    char  *channel_name;
    time_t timestamp;
};

RCDNews *rcd_news_parse   (xmlNode *item_node);
void     rcd_news_free    (RCDNews *);

void     rcd_news_add     (RCDNews *);
void     rcd_news_clear   (void);

void     rcd_news_foreach (RCDNewsFn fn, gpointer user_data);





#endif /* __RCD_NEWS_H__ */

