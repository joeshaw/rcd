/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-query.c
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
#include "rcd-query.h"

#include <glib.h>
#include <xmlrpc.h>
#include <libredcarpet.h>
#include "rcd-rpc.h"

static struct QueryTypeStrings {
    RCDQueryType type;
    const char *str;
} query2str[] = {

    { RCD_QUERY_EQUAL, "is" },
    { RCD_QUERY_EQUAL, "eq" },
    { RCD_QUERY_EQUAL, "==" },
    { RCD_QUERY_EQUAL, "=" },

    { RCD_QUERY_NOT_EQUAL, "is not" },
    { RCD_QUERY_NOT_EQUAL, "ne" },
    { RCD_QUERY_NOT_EQUAL, "!=" },

    { RCD_QUERY_CONTAINS, "contains" },

    { RCD_QUERY_CONTAINS_WORD, "contains_word" },

    { RCD_QUERY_NOT_CONTAINS, "!contains" },

    { RCD_QUERY_NOT_CONTAINS_WORD, "!contains_word" },
    
    { RCD_QUERY_GT, ">" },
    { RCD_QUERY_GT, "gt" },

    { RCD_QUERY_LT, "<" },
    { RCD_QUERY_LT, "lt" },

    { RCD_QUERY_GT_EQ, ">="},
    { RCD_QUERY_GT_EQ, "gteq"},

    { RCD_QUERY_LT_EQ, "<="},
    { RCD_QUERY_LT_EQ, "lteq"},

    { RCD_QUERY_BEGIN_OR, "begin-or" },
    { RCD_QUERY_END_OR,   "end-or" },

    { RCD_QUERY_INVALID,   NULL }
};
        

RCDQueryType
rcd_query_type_from_string (const char *str)
{
    int i;
    g_return_val_if_fail (str && *str, RCD_QUERY_INVALID);
    for (i = 0; query2str[i].type != RCD_QUERY_INVALID; ++i) {
        if (! g_strcasecmp (str, query2str[i].str))
            return query2str[i].type;
    }
    return RCD_QUERY_INVALID;
}

const char *
rcd_query_type_to_string (RCDQueryType type)
{
    int i;

    g_return_val_if_fail (type != RCD_QUERY_INVALID, "[Invalid]");
    g_return_val_if_fail (type != RCD_QUERY_LAST, "[Invalid:Last]");

    for (i = 0; query2str[i].type != RCD_QUERY_LAST; ++i) {
        if (query2str[i].type == type)
            return query2str[i].str;
    }

    return "[Invalid:NotFound]";
}

gboolean
rcd_query_type_int_compare (RCDQueryType type,
                            gint x, gint y)
{
    g_return_val_if_fail (type != RCD_QUERY_CONTAINS
                          && type != RCD_QUERY_NOT_CONTAINS, FALSE);

    switch (type) {

    case RCD_QUERY_EQUAL:
        return x == y;
        
    case RCD_QUERY_NOT_EQUAL:
        return x != y;

    case RCD_QUERY_GT:
        return x > y;

    case RCD_QUERY_LT:
        return x < y;

    case RCD_QUERY_GT_EQ:
        return x >= y;

    case RCD_QUERY_LT_EQ:
        return x <= y;

    default:
    }

    g_assert_not_reached ();
    return FALSE;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static char *
strstr_word (const char *haystack, const char *needle)
{
    const char *hay = haystack;
    while (*hay) {
        char *n = strstr (hay, needle);
        gboolean failed = FALSE;

        if (n == NULL)
            return NULL;

        if (n != haystack) {
            char *prev = g_utf8_prev_char (n);
            if (g_unichar_isalnum (g_utf8_get_char (prev)))
                failed = TRUE;
        }

        if (! failed) {
            char *next = n + strlen (needle);
            if (*next && g_unichar_isalnum (g_utf8_get_char (next)))
                failed = TRUE;
        }

        if (! failed)
            return n;

        hay = g_utf8_next_char (hay);
    }

    return NULL;
}

gboolean
rcd_query_match_string (RCDQueryPart *part,
                        const char *str)
{
    if (part->type == RCD_QUERY_CONTAINS) {
        return strstr (str, part->query_str) != NULL;
    } else if (part->type == RCD_QUERY_NOT_CONTAINS) {
        return strstr (str, part->query_str) == NULL;
    } else if (part->type == RCD_QUERY_CONTAINS_WORD) {
        return strstr_word (str, part->query_str) != NULL;
    } else if (part->type == RCD_QUERY_NOT_CONTAINS_WORD) {
        return strstr_word (str, part->query_str) == NULL;
    }
    
    return rcd_query_type_int_compare (part->type, strcmp (part->query_str, str), 0);
}

gboolean
rcd_query_match_string_ci (RCDQueryPart *part,
                           const char *str)
{
    char *str_folded;
    int rv;

    if (part->query_str_folded == NULL) {
        part->query_str_folded = g_utf8_casefold (part->query_str, -1);
    }

    str_folded = g_utf8_casefold (str, -1);

    if (part->type == RCD_QUERY_CONTAINS) {
        return strstr (str_folded, part->query_str_folded) != NULL;
    } else if (part->type == RCD_QUERY_NOT_CONTAINS) {
        return strstr (str_folded, part->query_str_folded) == NULL;
    } if (part->type == RCD_QUERY_CONTAINS_WORD) {
        return strstr_word (str_folded, part->query_str_folded) != NULL;
    } else if (part->type == RCD_QUERY_NOT_CONTAINS_WORD) {
        return strstr_word (str_folded, part->query_str_folded) == NULL;
    }

    rv = rcd_query_type_int_compare (part->type,
                                     strcmp (part->query_str_folded, str_folded),
                                     0);

    g_free (str_folded);

    return rv;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

gboolean
rcd_query_validate_bool (RCDQueryPart *part)
{
    if (part->type != RCD_QUERY_EQUAL
        && part->type != RCD_QUERY_NOT_EQUAL)
        return FALSE;

    if (! g_strcasecmp (part->query_str, "true")) {
        part->data = GINT_TO_POINTER (1);
    } else if (! g_strcasecmp (part->query_str, "false")) {
        part->data = GINT_TO_POINTER (0);
    } else {
        return FALSE;
    }

    return TRUE;
}

gboolean
rcd_query_match_bool (RCDQueryPart *part,
                      gboolean      val)
{
    gboolean match;

    match = part->data == (val ? GINT_TO_POINTER (1) : GINT_TO_POINTER (0));
    
    if (part->type == RCD_QUERY_EQUAL)
        return match;
    else if (part->type == RCD_QUERY_NOT_EQUAL)
        return ! match;

    g_assert_not_reached ();
    return FALSE;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static RCDQueryEngine *
lookup_engine (const char     *key, 
               RCDQueryEngine *query_engine)
{
    int i;

    for (i = 0; query_engine[i].key != NULL; ++i) {
        if (! g_strcasecmp (key, query_engine[i].key))
            return &query_engine[i];
    }

    return NULL;
}

gboolean
rcd_query_begin (RCDQueryPart *query_parts,
                 RCDQueryEngine *query_engine)
{
    int i, or_depth = 0;

    g_return_val_if_fail (query_engine != NULL, FALSE);

    if (query_parts == NULL)
        return TRUE;

    /* Sweep through and validate the parts. */
    for (i = 0; query_parts[i].type != RCD_QUERY_LAST; ++i) {

        RCDQueryEngine *eng = NULL;

        if (query_parts[i].type == RCD_QUERY_BEGIN_OR) {

            if (or_depth > 0) {
                g_warning ("Nested 'or' not allowed.");
                return FALSE;
            }

            ++or_depth;

        } else if (query_parts[i].type == RCD_QUERY_END_OR) {

            --or_depth;

            if (or_depth < 0) {
                g_warning ("Extra 'or' terminator found.");
                return FALSE;
            }

        } else {

            eng = lookup_engine (query_parts[i].key, query_engine);

            if (eng) {
                
                if (eng->validate && ! eng->validate (&query_parts[i]))
                    return FALSE;

                if (eng->match == NULL) {
                    g_warning ("Key \"%s\" lacks a match function.", query_parts[i].key);
                    return FALSE;
                }

           } else {
               g_warning ("Unknown part \"%s\"", query_parts[i].key);
                return FALSE;
            }
        }

        query_parts[i].query_str_folded = NULL;
        query_parts[i].engine           = eng;
        query_parts[i].processed        = FALSE;
    }

    if (or_depth > 0) {
        g_warning ("Unterminated 'or' in expression.");
        return FALSE;
    }

    /* If we made it this far, our query must be OK.  Call each part initializer. */
    for (i = 0; query_parts[i].type != RCD_QUERY_LAST; ++i) {
        
        if (query_parts[i].engine && query_parts[i].engine->initialize)
            query_parts[i].engine->initialize (&query_parts[i]);

     
    }

    return TRUE;
}

gboolean
rcd_query_match (RCDQueryPart   *query_parts,
                 RCDQueryEngine *query_engine,
                 gpointer        data)
{
    int i;
    int or_depth = 0, or_expr_count = 0;
    gboolean or_val = FALSE;

    g_return_val_if_fail (query_engine != NULL, FALSE);

    if (query_parts == NULL)
        return TRUE;

    for (i = 0; query_parts[i].type != RCD_QUERY_LAST; ++i) {

        if (! query_parts[i].processed) {

            if (query_parts[i].type == RCD_QUERY_BEGIN_OR) {

                ++or_depth;
                or_expr_count = 0;
                or_val = FALSE;

            } else if (query_parts[i].type == RCD_QUERY_END_OR) {

                --or_depth;
                if (or_expr_count > 0 && ! or_val)
                    return FALSE;

            } else {

                RCDQueryEngine *engine = query_parts[i].engine;
                gboolean matched;
            
                g_assert (engine != NULL);
                g_assert (engine->match != NULL);

                matched = engine->match (&query_parts[i], data);

                if (or_depth > 0) {
                    ++or_expr_count;
                    if (matched)
                        or_val = TRUE;
                } else {
                    if (! matched)
                        return FALSE;
                }
            }
        }
    }

    return TRUE;
}

void
rcd_query_end (RCDQueryPart *query_parts,
               RCDQueryEngine *query_engine)
{
    int i;

    g_return_if_fail (query_engine != NULL);

    if (query_parts == NULL)
        return;

    for (i = 0; query_parts[i].key != NULL; ++i) {

        if (query_parts[i].engine && query_parts[i].engine->finalize)
            query_parts[i].engine->finalize (&query_parts[i]);

        query_parts[i].engine = NULL;

        if (query_parts[i].query_str_folded) {
            g_free (query_parts[i].query_str_folded);
            query_parts[i].query_str_folded = NULL;
        }
    }
}

