/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-pending.c
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
#include "rcd-pending.h"

#include <math.h>
#include <libredcarpet.h>
#include "rcd-marshal.h"

static GObjectClass *parent_class;

enum {
    UPDATE,
    COMPLETE,
    LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

const char *
rcd_pending_status_to_string (RCDPendingStatus status)
{
    switch (status) {
    
    case RCD_PENDING_STATUS_PRE_BEGIN:
        return "pre-begin";
        
    case RCD_PENDING_STATUS_RUNNING:
        return "running";

    case RCD_PENDING_STATUS_BLOCKING:
        return "blocking";

    case RCD_PENDING_STATUS_ABORTED:
        return "aborted";

    case RCD_PENDING_STATUS_FAILED:
        return "failed";

    case RCD_PENDING_STATUS_FINISHED:
        return "finished";

    case RCD_PENDING_STATUS_INVALID:
    default:
        return "invalid";
        
    }
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static void
rcd_pending_finalize (GObject *obj)
{
    RCDPending *pending = (RCDPending *) obj;

    g_free (pending->description);
    g_free (pending->error_msg);

    if (parent_class->finalize)
        parent_class->finalize (obj);
}

static void
rcd_pending_update_handler (RCDPending *pending)
{
    rc_debug (RC_DEBUG_LEVEL_INFO,
              "id=%d '%s' %.1f%%/%ds remaining (%s)",
              pending->id, pending->description,
              pending->percent_complete,
              rcd_pending_get_remaining_secs (pending),
              rcd_pending_status_to_string (pending->status));
}

static void
rcd_pending_complete_handler (RCDPending *pending)
{
    rc_debug (RC_DEBUG_LEVEL_INFO,
              "id=%d COMPLETE '%s' time=%ds (%s)",
              pending->id, pending->description,
              rcd_pending_get_elapsed_secs (pending),
              rcd_pending_status_to_string (pending->status));
}

static void
rcd_pending_class_init (RCDPendingClass *klass)
{
    GObjectClass *obj_class = (GObjectClass *) klass;

    parent_class = g_type_class_peek_parent (klass);

    obj_class->finalize = rcd_pending_finalize;

    klass->update = rcd_pending_update_handler;
    klass->complete = rcd_pending_complete_handler;

    signals[UPDATE] =
        g_signal_new ("update",
                      G_TYPE_FROM_CLASS (klass),
                      G_SIGNAL_RUN_FIRST,
                      G_STRUCT_OFFSET (RCDPendingClass, update),
                      NULL, NULL,
                      rcd_marshal_VOID__VOID,
                      G_TYPE_NONE, 0);

    signals[COMPLETE] =
        g_signal_new ("complete",
                      G_TYPE_FROM_CLASS (klass),
                      G_SIGNAL_RUN_FIRST,
                      G_STRUCT_OFFSET (RCDPendingClass, complete),
                      NULL, NULL,
                      rcd_marshal_VOID__VOID,
                      G_TYPE_NONE, 0);
}

static void
rcd_pending_init (RCDPending *pending)
{
    pending->status = RCD_PENDING_STATUS_PRE_BEGIN;
}

GType
rcd_pending_get_type (void)
{
    static GType type = 0;

    if (! type) {
        static GTypeInfo type_info = {
            sizeof (RCDPendingClass),
            NULL, NULL,
            (GClassInitFunc) rcd_pending_class_init,
            NULL, NULL,
            sizeof (RCDPending),
            0,
            (GInstanceInitFunc) rcd_pending_init
        };

        type = g_type_register_static (G_TYPE_OBJECT,
                                       "RCDPending",
                                       &type_info,
                                       0);
    }

    return type;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static GHashTable *id_hash = NULL;

RCDPending *
rcd_pending_new (const char *description)
{
    static gint next_id = 1;

    RCDPending *pending = g_object_new (RCD_TYPE_PENDING, NULL);

    pending->description = g_strdup (description);
    pending->id = next_id;
    
    if (id_hash == NULL) {
        id_hash = g_hash_table_new (NULL, NULL);
    }

    g_hash_table_insert (id_hash,
                         GINT_TO_POINTER (next_id),
                         g_object_ref (pending));

    ++next_id;
    
    return pending;
}

RCDPending *
rcd_pending_lookup_by_id (gint id)
{
    RCDPending *pending;

    g_return_val_if_fail (id > 0, NULL);

    if (id_hash == NULL)
        return NULL;

    pending = g_hash_table_lookup (id_hash, GINT_TO_POINTER (id));

    if (pending) {
        g_return_val_if_fail (pending->id == id, NULL);
    }

    return pending;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static void
rcd_pending_timestamp (RCDPending *pending)
{
    time (&pending->last_time);
}

void
rcd_pending_begin (RCDPending *pending)
{
    g_return_if_fail (RCD_IS_PENDING (pending));
    g_return_if_fail (pending->status == RCD_PENDING_STATUS_PRE_BEGIN);
    
    pending->status = RCD_PENDING_STATUS_RUNNING;
    time (&pending->start_time);

    rcd_pending_update (pending, 0);
}

void
rcd_pending_update (RCDPending *pending,
                    double      percent_complete)
{
    g_return_if_fail (RCD_IS_PENDING (pending));
    g_return_if_fail (pending->status == RCD_PENDING_STATUS_RUNNING);
    g_return_if_fail (0 <= percent_complete && percent_complete <= 100);

    rcd_pending_timestamp (pending);

    pending->percent_complete = percent_complete;

    g_signal_emit (pending, signals[UPDATE], 0);
}

void
rcd_pending_finished (RCDPending *pending,
                      gint        retval)
{
    g_return_if_fail (RCD_IS_PENDING (pending));
    g_return_if_fail (pending->status == RCD_PENDING_STATUS_RUNNING);

    rcd_pending_timestamp (pending);

    pending->status = RCD_PENDING_STATUS_FINISHED;
    pending->retval = retval;

    g_signal_emit (pending, signals[COMPLETE], 0);
}

void
rcd_pending_abort (RCDPending *pending,
                   gint        retval)
{
    g_return_if_fail (RCD_IS_PENDING (pending));
    g_return_if_fail (pending->status == RCD_PENDING_STATUS_RUNNING);

    rcd_pending_timestamp (pending);

    pending->status = RCD_PENDING_STATUS_ABORTED;
    pending->retval = retval;

    g_signal_emit (pending, signals[COMPLETE], 0);
}

void
rcd_pending_fail (RCDPending *pending,
                  gint        retval,
                  const char *error_msg)
{
    g_return_if_fail (RCD_IS_PENDING (pending));
    g_return_if_fail (pending->status == RCD_PENDING_STATUS_RUNNING);

    rcd_pending_timestamp (pending);

    pending->status    = RCD_PENDING_STATUS_FAILED;
    pending->retval    = retval;
    pending->error_msg = g_strdup (error_msg);

    g_signal_emit (pending, signals[COMPLETE], 0);
}

const char *
rcd_pending_get_description (RCDPending *pending)
{
    g_return_val_if_fail (RCD_IS_PENDING (pending), NULL);

    return pending->description ? pending->description : "(no description)";
}

void
rcd_pending_set_description (RCDPending *pending,
                             const char *desc)
{
    g_return_if_fail (RCD_IS_PENDING (pending));

    g_free (pending->description);
    pending->description = g_strdup (desc);
}

gint
rcd_pending_get_id (RCDPending *pending)
{
    g_return_val_if_fail (RCD_IS_PENDING (pending), -1);

    return pending->id;
}

RCDPendingStatus
rcd_pending_get_status (RCDPending *pending)
{
    g_return_val_if_fail (RCD_IS_PENDING (pending), RCD_PENDING_STATUS_INVALID);
    
    return pending->status;
}

double
rcd_pending_get_percent_complete (RCDPending *pending)
{
    g_return_val_if_fail (RCD_IS_PENDING (pending), -1);

    return pending->percent_complete;
}

time_t
rcd_pending_get_start_time (RCDPending *pending)
{
    g_return_val_if_fail (RCD_IS_PENDING (pending), (time_t) 0);

    return pending->start_time;
}

time_t
rcd_pending_get_last_time (RCDPending *pending)
{
    g_return_val_if_fail (RCD_IS_PENDING (pending), (time_t) 0);

    return pending->last_time;
}

gint
rcd_pending_get_elapsed_secs (RCDPending *pending)
{
    time_t t;

    g_return_val_if_fail (RCD_IS_PENDING (pending), -1);

    if (pending->start_time == (time_t) 0)
        return -1;

    if (pending->status == RCD_PENDING_STATUS_RUNNING)
        time (&t);
    else
        t = pending->last_time;

    return (gint)(t - pending->start_time);
}

gint
rcd_pending_get_expected_secs (RCDPending *pending)
{
    double t;

    g_return_val_if_fail (RCD_IS_PENDING (pending), -1);

    if (pending->start_time == (time_t) 0
        || pending->last_time == (time_t) 0
        || pending->start_time == pending->last_time
        || pending->percent_complete <= 1e-8)
        return -1;

    t = (pending->last_time - pending->start_time) / (pending->percent_complete / 100);
    return (gint) rint (t);
}

gint
rcd_pending_get_remaining_secs (RCDPending *pending)
{
    gint elapsed, expected;

    g_return_val_if_fail (RCD_IS_PENDING (pending), -1);

    elapsed = rcd_pending_get_elapsed_secs (pending);
    if (elapsed < 0)
        return -1;

    expected = rcd_pending_get_expected_secs (pending);
    if (expected < 0)
        return -1;

    return elapsed <= expected ? expected - elapsed : 0;
}

void
rcd_pending_add_message (RCDPending *pending, const char *message)
{
    g_return_if_fail (RCD_IS_PENDING (pending));
    g_return_if_fail (message);

    pending->messages = g_slist_append (pending->messages, g_strdup (message));
} /* rcd_pending_add_message */

GSList *
rcd_pending_get_messages (RCDPending *pending)
{
    g_return_val_if_fail (RCD_IS_PENDING (pending), NULL);

    return pending->messages;
} /* rcd_pending_get_messages */

const char *
rcd_pending_get_latest_message (RCDPending *pending)
{
    g_return_val_if_fail (RCD_IS_PENDING (pending), NULL);

    if (!pending->messages)
        return NULL;

    return (const char *) g_slist_last (pending->messages)->data;
} /* rcd_pending_get_latest_message */
