/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-fetch.h
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

#ifndef __RCD_FETCH_H__
#define __RCD_FETCH_H__

#include <libredcarpet.h>

#include "rcd-transfer-pool.h"
#include "rcd-xmlrpc.h"

/*
 * Functions marked "local" try to read the data from a last known good
 * file and return FALSE if unable to load from it.
 */

/*
 * Registers the daemon with the server.  This is done automatically at
 * startup when in premium services mode and an org id is set, with a
 * NULL activation code and email.  This is the "new" automatic style.
 *
 * "Old", RCX-style activation with an activation code and email address
 * is also possible, by passing in non-NULL values for activation_code
 * and email.  If in premium services mode, this will connect to the
 * currently set host.  Otherwise, it will connect to the default
 * activation host.
 *
 * As of 1.4 a third field, "alias" was added.  It specifies an alias
 * for the machine when it can't be readily identified by hostname.
 *
 */
xmlrpc_value *rcd_fetch_register (xmlrpc_env *env,
                                  const char *activation_code,
                                  const char *email,
                                  const char *alias);

/*
 * Download the (un)supported/deprecated distro information from the server.
 * This -must- be done before the RCWorld is initialized.  Returns TRUE on
 * success.
 */
gboolean rcd_fetch_distro       (void);
gboolean rcd_fetch_distro_local (void);

/*
 * Set up an RCDTransferPool to download all of the packages specified.
 */
void rcd_fetch_packages (RCDTransferPool *pool,
                         RCPackageSList  *packages);

#endif /* __RCD_FETCH_H__ */

