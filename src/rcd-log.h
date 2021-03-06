/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-log.h
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

#ifndef __RCD_LOG_H__
#define __RCD_LOG_H__

#include "rcd-log-entry.h"
#include "rcd-query.h"

/* If log_path is NULL, use the default path */
void rcd_log_init (const char *log_path);

void rcd_log_reinit (void);

void rcd_log (RCDLogEntry *entry);

void rcd_log_query (RCDQueryPart *query_parts,
                    RCDLogEntryFn entry_fn,
                    gpointer      user_data);

#endif /* __RCD_LOG_H__ */

