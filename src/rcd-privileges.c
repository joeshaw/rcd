/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-privileges.c
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
#include "rcd-privileges.h"

#include <libredcarpet.h>

/* We start our assigned privileges as 1<<1, so that
   the magic superuser privilege (~0) has a bit set that
   no other privilege will contain. */
static int priv_shift = 1;
static GHashTable *priv_hash = NULL;

#define SU_PRIV (~(guint64)0)

RCDPrivileges
rcd_privileges_register (const char *priv_name)
{
    gchar *folded_name;
    guint64 *priv;
    g_return_val_if_fail (priv_name && *priv_name, 0);

    if (strchr (priv_name, ',') || strchr (priv_name, ':')) {
        rc_debug (RC_DEBUG_LEVEL_ERROR,
                  "Illegal privilege name: '%s'", priv_name);
        return 0;
    }

    folded_name = g_utf8_casefold (priv_name, -1);

    g_assert (priv_hash != NULL);

    if (g_hash_table_lookup (priv_hash, folded_name) != NULL) {
        rc_debug (RC_DEBUG_LEVEL_ERROR,
                  "Privilege name collision: '%s'", folded_name);
        g_free (folded_name);
        return 0;
    }

    priv = g_new0 (guint64, 1);
    *priv = (guint64)1 << priv_shift;
    ++priv_shift;

    g_hash_table_insert (priv_hash, folded_name, priv);

    return *priv;
}

struct PrivilegesForeachInfo {
    RCDPrivilegesFn fn;
    gpointer        user_data;
};

static void
priv_foreach_cb (gpointer key,
                 gpointer val,
                 gpointer user_data)
{
    const char *name = key;
    RCDPrivileges *priv = val;
    struct PrivilegesForeachInfo *info = user_data;

    g_assert (name && priv);
    info->fn (*priv, name, info->user_data);
}

void
rcd_privileges_foreach (RCDPrivilegesFn fn,
                         gpointer       user_data)
{
    struct PrivilegesForeachInfo info;

    g_return_if_fail (fn != NULL);

    if (priv_hash == NULL)
        return;

    info.fn = fn;
    info.user_data = user_data;

    g_hash_table_foreach (priv_hash, priv_foreach_cb, &info);
}

RCDPrivileges
rcd_privileges_from_string (const char *priv_str)
{
    char *folded_priv_str;
    char **strv;
    int i;
    RCDPrivileges accumulated_priv = 0;

    if (! (priv_str && *priv_str))
        return 0;

    folded_priv_str = g_utf8_casefold (priv_str, -1);
    strv = g_strsplit (folded_priv_str, ",", 0);
        
    for (i = 0; strv[i] != NULL; ++i) {
        RCDPrivileges *priv = NULL;
        
        g_strstrip (strv[i]);
        
        if (! strcmp (strv[i], "superuser")) {
            accumulated_priv = SU_PRIV;
            break;
        }
        
        if (priv_hash)
            priv = g_hash_table_lookup (priv_hash, strv[i]);
        
        if (priv) {
            accumulated_priv |= *priv;
        } else {
            rc_debug (RC_DEBUG_LEVEL_WARNING,
                      "Ignoring unknown privilege '%s'", strv[i]);
        }
    }
    
    g_strfreev (strv);
    g_free (folded_priv_str);

    return accumulated_priv;
}

struct PrivToStringInfo {
    RCDPrivileges priv;
    GString *string;
};

static void
priv_to_string_cb (RCDPrivileges this_priv,
                   const char  *name,
                   gpointer     user_data)
{
    struct PrivToStringInfo *info = user_data;

    if (info->priv & this_priv) {
        info->priv &= ~this_priv;
        if (info->string->len > 0)
            g_string_append (info->string, ", ");
        g_string_append (info->string, name);
    }
}

char *
rcd_privileges_to_string (RCDPrivileges priv)
{
    struct PrivToStringInfo info;

    if (priv == 0)
        return g_strdup ("");

    if (priv == SU_PRIV)
        return g_strdup ("superuser");

    info.priv = priv;
    info.string = g_string_new ("");

    rcd_privileges_foreach (priv_to_string_cb, &info);

    if (info.priv) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Unknown left-over bits in RCDPrivileges (%lx)", info.priv);
    }

    return g_string_free (info.string, FALSE);
}

void
rcd_privileges_init (void)
{
    const char *base_privileges[] = 
        { "view", "install", "remove", "upgrade", "subscribe", NULL };
    int i;

    static gboolean inited = FALSE;

    if (inited)
        return;
    inited = TRUE;

    priv_hash = g_hash_table_new (g_str_hash, g_str_equal);
    
    for (i = 0; base_privileges[i]; ++i)
        rcd_privileges_register (base_privileges[i]);
}
