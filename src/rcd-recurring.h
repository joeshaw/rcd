/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-recurring.h
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

#ifndef __RCD_RECURRING_H__
#define __RCD_RECURRING_H__

#include <time.h>
#include <glib.h>

typedef struct _RCDRecurring RCDRecurring;

typedef void (*RCDRecurringFn) (RCDRecurring *rec, gpointer user_data);

struct _RCDRecurring {

    GQuark tag;

    void   (*destroy) (RCDRecurring *);
    void   (*execute) (RCDRecurring *);
    
    /* Returns when the first execution should occur.
       "0" means "right now". */
    time_t (*first)   (RCDRecurring *, time_t now);

    /* Returns when the next execution should occur.
       "0" means "never". */
    time_t (*next)    (RCDRecurring *, time_t previous);

    /* private */
    time_t   when;
    gboolean removed;
};

/* If we rcd_recurring_add a RCDRecurring that has already been added,
   it gets "rescheduled": the first method is called again, and the
   results are used to set the item's next execution time. */
void  rcd_recurring_add     (RCDRecurring *recurring);

/* It should be safe to add or removed items inside of
   rcd_recurring_foreach's iterator function. */
void  rcd_recurring_foreach (GQuark         tag,
                             RCDRecurringFn fn,
                             gpointer       user_data);

/* Recurring items that we remove are automatically destroyed. */
void  rcd_recurring_remove  (RCDRecurring *recurring);

void  rcd_recurring_reschedule (RCDRecurring *recurring);

void rcd_recurring_block    (void);

void rcd_recurring_allow    (void);

#endif /* __RCD_RECURRING_H__ */

