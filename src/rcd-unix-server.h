/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#ifndef __RCD_UNIX_SERVER_H__
#define __RCD_UNIX_SERVER_H__

#include <glib.h>
#include <sys/types.h>

typedef struct _RCDUnixServerHandle RCDUnixServerHandle;

typedef GByteArray *(*RCDUnixServerCallback) (RCDUnixServerHandle *handle);

struct _RCDUnixServerHandle {
    GByteArray *data;

    gboolean cred_available;
    pid_t pid;
    uid_t uid;
    gid_t gid;

    RCDUnixServerCallback cb;
};

void rcd_unix_server_run_async(RCDUnixServerCallback callback);

#endif /* __RCD_UNIX_SERVER_H__ */
