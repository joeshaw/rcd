/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-query.h
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

#ifndef __RCD_QUERY_H__
#define __RCD_QUERY_H__

#include "libredcarpet.h"

typedef enum {
    RCD_QUERY_IS,
    RCD_QUERY_SUBSTR,
    RCD_QUERY_GT,
    RCD_QUERY_LT,
    RCD_QUERY_GT_EQ,
    RCD_QUERY_LT_EQ,
    RCD_QUERY_LAST,
    RCD_QUERY_INVALID
} RCDQueryType;

typedef struct _RCDQueryPart RCDQueryPart;
struct _RCDQueryPart {
    char        *key;
    RCDQueryType type;
    char        *query_str;
    guint        negate : 1;

    /* for internal use only */
    guint    processed : 1; 
    gpointer data;
};

RCDQueryType rcd_query_type_from_string (const char *str);

const char  *rcd_query_type_to_string   (RCDQueryType type);

gboolean     rcd_query_type_compare     (RCDQueryType type,
                                         gint x, gint y);

gint rcd_query (RCWorld      *world,
                RCDQueryPart *parts_array,
                RCPackageFn   fn,
                gpointer      user_data);

#endif /* __RC_QUERY_H__ */

