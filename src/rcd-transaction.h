/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-transaction.h
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

#ifndef __RCD_TRANSACTION_H__
#define __RCD_TRANSACTION_H__

#include <libredcarpet.h>

int rcd_transaction_begin (RCWorld        *world,
                           RCPackageSList *install_packages,
                           RCPackageSList *remove_packages,
                           gboolean        dry_run,
                           const char     *client_id,
                           const char     *client_version,
                           const char     *client_host,
                           const char     *client_user);

gboolean rcd_transaction_is_valid (int transaction_id);

RCPackageSList *rcd_transaction_get_install_packages (int transaction_id);

int rcd_transaction_get_package_download_id (int transaction_id);

/*
 * Global transaction locks.  rcd_transaction_begin() will lock and
 * unlock as necessary, so make sure to check if it is locked before
 * trying to lock or unlock it.
 */

void     rcd_transaction_lock      (void);
void     rcd_transaction_unlock    (void);
gboolean rcd_transaction_is_locked (void);

#endif /* __RCD_TRANSACTION_H__ */
