/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-transact-log.h
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

#ifndef __RCD_TRANSACT_LOG_H__
#define __RCD_TRANSACT_LOG_H__

#include <libredcarpet.h>

char **rcd_transact_log_send_transaction (RCPackageSList  *install_packages,
                                          RCPackageSList  *remove_packages,
                                          const char      *client_id,
                                          const char      *client_version);

void rcd_transact_log_send_success       (char           **tid,
                                          gboolean         successful,
                                          const char      *msg);

#endif /* __RCD_TRANSACT_LOG_H__ */
