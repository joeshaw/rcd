/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-transfer-http.h
 *
 * Copyright (C) 2000-2002 Ximian, Inc.
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

#ifndef __RCD_TRANSFER_HTTP_H__
#define __RCD_TRANSFER_HTTP_H__

#include "rcd-transfer.h"

typedef struct _RCDTransferProtocolHTTP RCDTransferProtocolHTTP;

struct _RCDTransferProtocolHTTP {
    RCDTransferProtocol parent;

    SoupSession *session;
    SoupMessage *message;

    const char *method;

    char *request_body;
    gsize request_length;

    GHashTable *request_headers;
    GHashTable *response_headers;
};

RCDTransferProtocol *rcd_transfer_protocol_http_new (void);

void        rcd_transfer_protocol_http_set_method (
    RCDTransferProtocolHTTP *protocol,
    const char              *method);

void        rcd_transfer_protocol_http_set_request_body (
    RCDTransferProtocolHTTP *protocol,
    char                    *body,
    gsize                    length);

void        rcd_transfer_protocol_http_set_request_header (
    RCDTransferProtocolHTTP *protocol,
    const char              *header,
    const char              *value);

const char *rcd_transfer_protocol_http_get_response_header (
    RCDTransferProtocolHTTP *protocol,
    const char              *header);

#endif /* __RCD_TRANSFER_HTTP_H__ */

