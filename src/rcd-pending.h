/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-pending.h
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

#ifndef __RCD_PENDING_H__
#define __RCD_PENDING_H__

#include <time.h>
#include <glib-object.h>


typedef   enum _RCDPendingStatus RCDPendingStatus;
typedef struct _RCDPending       RCDPending;
typedef struct _RCDPendingClass  RCDPendingClass;

enum _RCDPendingStatus {
    RCD_PENDING_STATUS_INVALID = 0,
    RCD_PENDING_STATUS_PRE_BEGIN,
    RCD_PENDING_STATUS_RUNNING,
    RCD_PENDING_STATUS_BLOCKING,
    RCD_PENDING_STATUS_ABORTED,
    RCD_PENDING_STATUS_FAILED,
    RCD_PENDING_STATUS_FINISHED
};

const char *rcd_pending_status_to_string (RCDPendingStatus status);

#define RCD_INVALID_PENDING_ID 0


struct _RCDPending {
    GObject parent;

    char *description;
    gint id;

    RCDPendingStatus status;

    double percent_complete;

    int completed_size;
    int total_size;

    time_t start_time;
    time_t last_time;
    time_t poll_time;

    gint retval;
    char *error_msg;

    GSList *messages;
};

struct _RCDPendingClass {
    GObjectClass parent_class;

    void (*update) (RCDPending *);
    void (*complete) (RCDPending *);
    void (*message) (RCDPending *);
};

#define RCD_TYPE_PENDING            (rcd_pending_get_type ())
#define RCD_PENDING(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), \
                                     RCD_TYPE_PENDING, RCDPending))
#define RCD_PENDING_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), \
                                     RCD_TYPE_PENDING, RCDPendingClass))
#define RCD_IS_PENDING(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), \
                                     RCD_TYPE_PENDING))
#define RCD_IS_PENDING_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), \
                                     RCD_TYPE_PENDING))

GType rcd_pending_get_type (void);

RCDPending *rcd_pending_new                (const char *description);
RCDPending *rcd_pending_lookup_by_id       (gint id);
GSList     *rcd_pending_get_all_active_ids (void);

void rcd_pending_begin    (RCDPending *);

void rcd_pending_update         (RCDPending *, double percent_complete);
void rcd_pending_update_by_size (RCDPending *, int size, int total_size);

void rcd_pending_finished (RCDPending *, gint retval);
void rcd_pending_abort    (RCDPending *, gint retval);
void rcd_pending_fail     (RCDPending *, gint retval, const char *error_msg);

gboolean rcd_pending_is_active (RCDPending *);

const char      *rcd_pending_get_description      (RCDPending *);
void             rcd_pending_set_description      (RCDPending *, const char *desc);
gint             rcd_pending_get_id               (RCDPending *);
RCDPendingStatus rcd_pending_get_status           (RCDPending *);
double           rcd_pending_get_percent_complete (RCDPending *);
int              rcd_pending_get_completed_size   (RCDPending *);
int              rcd_pending_get_total_size       (RCDPending *);
time_t           rcd_pending_get_start_time       (RCDPending *);
time_t           rcd_pending_get_last_time        (RCDPending *);

gint             rcd_pending_get_elapsed_secs     (RCDPending *);
gint             rcd_pending_get_expected_secs    (RCDPending *);
gint             rcd_pending_get_remaining_secs   (RCDPending *);
const char      *rcd_pending_get_error_msg        (RCDPending *);

void             rcd_pending_add_message        (RCDPending *,
                                                 const char *message);
GSList          *rcd_pending_get_messages       (RCDPending *);
const char      *rcd_pending_get_latest_message (RCDPending *);
#endif /* __RCD_PENDING_H__ */



