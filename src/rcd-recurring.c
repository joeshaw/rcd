/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-recurring.c
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
#include "rcd-recurring.h"

#include <libredcarpet.h>

static GList *recurring_list = NULL;
static guint  recurring_timeout_id = 0;
static gint   recurring_lock = 0;

static gboolean
rcd_recurring_execute (RCDRecurring *recurring)
{
    time_t next;

    g_return_val_if_fail (recurring != NULL, FALSE);

    if (recurring->execute)
        recurring->execute (recurring);

    ++recurring->count;
    recurring->prev = recurring->when;

    next = 0;
    if (recurring->next)
        recurring->when = recurring->next (recurring, recurring->when);

    return recurring->when;
}

static void
rcd_recurring_execute_list (void)
{
    static gboolean exec_lock = FALSE;
    GList *iter = recurring_list;
    time_t now;

    if (exec_lock)
        return;
    exec_lock = TRUE;

    time (&now);

    for (iter = recurring_list; iter != NULL; iter = iter->next) {
        RCDRecurring *recurring = iter->data;

        if (recurring->when <= now && ! recurring->removed) {
            /* rcd_recurring_execute returns FALSE if the event shouldn't
               happen again. */
            if (! rcd_recurring_execute (recurring))
                recurring->removed = TRUE;
        }
    }

    /* Do a second pass to clean out removed items. */
    iter = recurring_list;
    while (iter != NULL) {
        RCDRecurring *recurring = iter->data;
        GList *next = iter->next;
        
        if (recurring->removed) {
            if (recurring->destroy)
                recurring->destroy (recurring);
            recurring_list = g_list_delete_link (recurring_list, iter);
        }

        iter = next;
    }

    exec_lock = FALSE;
}

static time_t
rcd_recurring_next_action (void)
{
    time_t next = 0;
    GList *iter;

    for (iter = recurring_list; iter != NULL; iter = iter->next) {
        RCDRecurring *recurring = iter->data;
        if (! recurring->removed) {
            if (next == 0 || recurring->when < next)
                next = recurring->when;
        }
    }

    return next;
}

static gboolean
rcd_recurring_timeout_cb (gpointer execute_if_null)
{
    static void rcd_recurring_setup_timeout (void);

    rcd_recurring_execute_list ();

    recurring_timeout_id = 0;
    rcd_recurring_setup_timeout ();

    return FALSE;
}

static void
rcd_recurring_setup_timeout (void)
{
    time_t next = 0;

    if (recurring_lock > 0)
        return;

    if (recurring_timeout_id)
        g_source_remove (recurring_timeout_id);

    next = rcd_recurring_next_action ();

    if (next) {
        time_t now;
        int delay;

        time (&now);
    
        delay = (next - now) * 1000;
        if (delay < 1)
            delay = 1;

        recurring_timeout_id = g_timeout_add (delay,
                                               rcd_recurring_timeout_cb,
                                               NULL);
    }
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

gchar *
rcd_recurring_get_label (RCDRecurring *recurring)
{
    g_return_val_if_fail (recurring != NULL, NULL);

    if (recurring->label)
        return recurring->label (recurring);

    return g_strdup (g_quark_to_string (recurring->tag));
}

void
rcd_recurring_add (RCDRecurring *recurring)
{
    g_return_if_fail (recurring != NULL);

    recurring->when = 0;
    recurring->removed = FALSE;

    if (recurring->first) {
        time_t now;
        time (&now);
        recurring->when = recurring->first (recurring, now);
    }

    if (recurring->when == 0) {
        time (& recurring->when);
    }
    
    if (g_list_find (recurring_list, recurring) == NULL) {
        recurring_list = g_list_prepend (recurring_list,
                                         recurring);
    } 

    rcd_recurring_setup_timeout ();
}

void
rcd_recurring_foreach (GQuark         tag,
                       RCDRecurringFn fn,
                       gpointer       user_data)
{
    GList *iter;

    if (fn == NULL)
        return;

    iter = recurring_list;
    while (iter != NULL) {
        RCDRecurring *recurring = iter->data;
        GList *next = iter->next;

        if (! recurring->removed) {
            if (tag == 0 || recurring->tag == tag)
                fn (recurring, user_data);
        }

        iter = next;
    }
}

/* The object is just flagged as removed; the actual removal occurs
   the next time that recurring_list is processed.  This ensures that
   it is safe to remove items from inside of _foreach iterators,
   inside execute methods, etc. */
void
rcd_recurring_remove (RCDRecurring *recurring)
{
    GList *node;

    if (recurring == NULL)
        return;

    node = g_list_find (recurring_list, recurring);
    if (node == NULL)
        return;

    recurring->removed = TRUE;

    rcd_recurring_setup_timeout ();
}

void
rcd_recurring_block (void)
{
    g_return_if_fail (recurring_lock >= 0);

    ++recurring_lock;

    if (recurring_timeout_id) {
        g_source_remove (recurring_timeout_id);
        recurring_timeout_id = 0;
    }
}

void
rcd_recurring_allow (void)
{
    g_return_if_fail (recurring_lock > 0);
    
    --recurring_lock;
    
    if (recurring_lock == 0) {
        rcd_recurring_setup_timeout ();
    }
}
