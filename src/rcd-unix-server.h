/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

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
