/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#ifndef __RCD_UNIX_SERVER_H__
#define __RCD_UNIX_SERVER_H__

#include <glib.h>

typedef GByteArray *(*RCDUnixServerCallback) (GByteArray *data);

void rcd_unix_server_run_async(RCDUnixServerCallback callback);

#endif /* __RCD_UNIX_SERVER_H__ */
