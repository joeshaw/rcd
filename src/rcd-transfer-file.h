/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-transfer-file.h
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

#ifndef __RCD_TRANSFER_FILE_H__
#define __RCD_TRANSFER_FILE_H__

#include "rcd-transfer.h"

typedef struct _RCDTransferProtocolFile RCDTransferProtocolFile;

struct _RCDTransferProtocolFile {
    RCDTransferProtocol parent;

    int watch;
};

RCDTransferProtocol *rcd_transfer_protocol_file_new (void);

#endif /* __RCD_TRANSFER_FILE_H__ */

