/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-transfer-http.h
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

#ifndef __RCD_TRANSFER_HTTP_H__
#define __RCD_TRANSFER_HTTP_H__

#include "rcd-transfer.h"

typedef struct _RCDTransferProtocolHTTP RCDTransferProtocolHTTP;

struct _RCDTransferProtocolHTTP {
    RCDTransferProtocol parent;

    RCDCacheEntry *entry;
    SoupMessage *message;

    gboolean cache_hit;
};

RCDTransferProtocol *rcd_transfer_protocol_http_new (void);

#endif /* __RCD_TRANSFER_HTTP_H__ */

