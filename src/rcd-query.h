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
    RCD_QUERY_EQUAL,
    RCD_QUERY_NOT_EQUAL,
    RCD_QUERY_CONTAINS,
    RCD_QUERY_NOT_CONTAINS,
    RCD_QUERY_GT,
    RCD_QUERY_LT,
    RCD_QUERY_GT_EQ,
    RCD_QUERY_LT_EQ,
    RCD_QUERY_LAST,
    RCD_QUERY_INVALID
} RCDQueryType;

typedef struct _RCDQueryPart RCDQueryPart;
typedef struct _RCDQueryEngine RCDQueryEngine;

typedef gboolean (*RCDQueryEngineValidateFn)   (RCDQueryPart *);
typedef void     (*RCDQueryEngineInitializeFn) (RCDQueryPart *);
typedef void     (*RCDQueryEngineFinalizeFn)   (RCDQueryPart *);
typedef gboolean (*RCDQueryEngineMatchFn)      (RCDQueryPart *, gpointer data);

struct _RCDQueryEngine {

    const char *key;

    RCDQueryEngineValidateFn   validate;
    RCDQueryEngineInitializeFn initialize;
    RCDQueryEngineFinalizeFn   finalize;
    RCDQueryEngineMatchFn      match;
};

struct _RCDQueryPart {

    char        *key;
    RCDQueryType type;
    char        *query_str;

    /* for internal use only */
    RCDQueryEngine *engine;
    gpointer        data;
    guint           processed : 1;
};


RCDQueryType rcd_query_type_from_string (const char *str);

const char  *rcd_query_type_to_string   (RCDQueryType type);

gboolean     rcd_query_type_int_compare (RCDQueryType type,
                                         gint x, gint y);


/* Useful pre-defined RCDQueryEngine components. */

gboolean     rcd_query_match_string (RCDQueryPart *part, const char *str);

gboolean     rcd_query_validate_bool   (RCDQueryPart *part);
gboolean     rcd_query_match_bool      (RCDQueryPart *part, gboolean val);


/* The query_parts array should be terminated by type RCD_QUERY_LAST.
   The query_engine array should be NULL-key terminated. */

gboolean     rcd_query_begin (RCDQueryPart   *query_parts,
                              RCDQueryEngine *query_engine);

gboolean     rcd_query_match (RCDQueryPart   *query_parts,  
                              RCDQueryEngine *query_engine, 
                              gpointer        data);

void         rcd_query_end   (RCDQueryPart   *query_parts,
                              RCDQueryEngine *query_engine);

#endif /* __RC_QUERY_H__ */

