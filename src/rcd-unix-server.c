/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-unix-server.c
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

#include <config.h>
#include "rcd-unix-server.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <libredcarpet.h>

#include "rcd-shutdown.h"

#define SOCKET_PATH "/var/run/rcd"

int
substring_index (char *str, int len, char *substr)
{
    int i, sublen = strlen (substr);
    
    for (i = 0; i <= len - sublen; ++i)
        if (str[i] == substr[0])
            if (memcmp (&str[i], substr, sublen) == 0)
                return i;
    
    return -1;
} /* substring_index */

#ifdef HAVE_SO_PEERCRED
static void
read_cred (GIOChannel *channel, RCDUnixServerHandle *handle)
{
    int sockfd;
    struct ucred cred;
    socklen_t size;
    int rc;

    sockfd = g_io_channel_unix_get_fd (channel);

    size = sizeof (cred);
    rc = getsockopt (sockfd, SOL_SOCKET, SO_PEERCRED, &cred, &size);

    if (rc < 0 || size != sizeof (cred)) {
        handle->cred_available = FALSE;

        rc_debug (RC_DEBUG_LEVEL_WARNING, "Couldn't get credentials");
    }
    else {
        handle->cred_available = TRUE;
        handle->pid = cred.pid;
        handle->uid = cred.uid;
        handle->gid = cred.gid;
    }
} /* read_cred */
#endif

static gboolean
read_data(GIOChannel *iochannel,
          GIOCondition condition,
          gpointer user_data)
{
    RCDUnixServerHandle *handle = user_data;
    GIOError err;
    char read_buf[4096];
    int bytes_read = 0;
    int total_read = 0;
    GByteArray *result;
    int bytes_written;
    int total_written = 0;

#ifdef HAVE_SO_PEERCRED
    if (!handle->cred_available)
        read_cred(iochannel, handle);
#endif

    /* If our channel has an error condition associated with it,
       free the handle and stop watching that iochannel. */
    if (condition & ~G_IO_IN) {
        g_byte_array_free(handle->data, TRUE);
        g_free(handle);
        return FALSE;
    }

    err = g_io_channel_read (iochannel,
                             read_buf,
                             sizeof (read_buf),
                             &bytes_read);

    if (bytes_read) {
        handle->data = g_byte_array_append (
            handle->data, read_buf, bytes_read);
        total_read += bytes_read;
    }

    if (err == G_IO_ERROR_AGAIN) {
            return TRUE;
    }
    
    if (err != G_IO_ERROR_NONE) {
        g_byte_array_free(handle->data, TRUE);

        return FALSE;
    }

    if (handle->data->len == 0) {
        g_byte_array_free(handle->data, TRUE);
        g_free(handle);
        return FALSE;
    }

    if (substring_index(handle->data->data, handle->data->len, "\r\n\r\n") < 0)
        return TRUE;

    result = (handle->cb) (handle);

    if (!result)
        return FALSE;

    do {
        err = g_io_channel_write(iochannel, 
                                 result->data + total_written,
                                 result->len - total_written,
                                 &bytes_written);
        
        total_written += bytes_written;
    } while ((err == G_IO_ERROR_NONE || err == G_IO_ERROR_AGAIN) &&
             total_written < result->len);

    g_byte_array_free(result, TRUE);
    g_byte_array_free(handle->data, TRUE);
    g_free(handle);

    g_io_channel_close(iochannel);

    return FALSE;
} /* read_data */

static gboolean
conn_accept(GIOChannel *serv_chan, GIOCondition condition, gpointer user_data)
{
    GIOChannel *conn_chan;
    int conn_fd;
    int serv_fd;
    fd_set fdset;
    struct timeval tv = {0, 0};
    socklen_t n;
    struct sockaddr sa;
    int flags;
    RCDUnixServerHandle *handle;

    serv_fd = g_io_channel_unix_get_fd(serv_chan);

try_again:
    FD_ZERO (&fdset);
    FD_SET (serv_fd, &fdset);

    if (select (serv_fd + 1, &fdset, NULL, NULL, &tv) == -1) {
        if (errno == EINTR)
            goto try_again;
        return TRUE;
    }

    n = sizeof (sa);
    
    if ((conn_fd = accept (serv_fd, &sa, &n)) == -1)
        return TRUE;

    flags = fcntl (conn_fd, F_GETFL, 0);
    fcntl (conn_fd, F_SETFL, flags | O_NONBLOCK);

    handle = g_new0(RCDUnixServerHandle, 1);
    handle->cred_available = FALSE;
    handle->data = g_byte_array_new();
    handle->cb = (RCDUnixServerCallback) user_data;

    conn_chan = g_io_channel_unix_new (conn_fd);
    g_io_add_watch (conn_chan, 
                    G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
                    (GIOFunc) read_data,
                    handle);
    g_io_channel_unref (conn_chan);

    return TRUE;
} /* conn_accept */

static void
shutdown_server_cb (gpointer user_data)
{
    int sockfd = GPOINTER_TO_INT (user_data);

    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Shutting down local server");

    close (sockfd);
    rc_rmdir (SOCKET_PATH);
} /* shutdown_server_cb */

int
rcd_unix_server_run_async(RCDUnixServerCallback callback)
{
    int sockfd;
    struct sockaddr_un servaddr;
    GIOChannel *iochannel;

    g_return_val_if_fail(callback, -1);

    /* 
     * We need to ignore SIGPIPE or else the daemon will die if the client
     * aborts or does some other sort of unsavory thing.
     */
    signal (SIGPIPE, SIG_IGN);

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Unable to open a domain socket");
        return -1;
    }

    rc_rmdir (SOCKET_PATH);

    /* If the socket is still around after we've tried to unlink it,
       it must be owned by someone else.  This means we won't be able
       to bind to it. */

    if (g_file_test (SOCKET_PATH, G_FILE_TEST_EXISTS)) {
        const char *message[] = {
            "",
            "The socket path " SOCKET_PATH " cannot be unlinked, which",
            "will almost certainly lead to rcd being unable to start up properly.",
            "To fix this, please remove " SOCKET_PATH " and re-start rcd.",
            "",
            NULL };
        int i;
        
        for (i = 0; message[i] != NULL; ++i)
            rc_debug (RC_DEBUG_LEVEL_WARNING, message[i]);

        return -1;
    }

    /*
     * Solaris doesn't have credential passing, so we can't verify the
     * user on the other end of the socket.  So if we don't have
     * SO_PEERCRED, make the socket directory mode 0700 so only root can
     * write to it.
     *
     * Why create a directory to put the socket into and not just make
     * the socket mode 0700?  A great question!  Solaris is a sucky
     * operating system and ignores permissions on domain sockets,
     * allowing any user to write to any socket that he can see.  To get
     * around this, we have to put the socket into a 0700 directory.
     * Sigh.
     */
    if (rc_mkdir (SOCKET_PATH,
#ifdef HAVE_SO_PEERCRED
                   0777
#else
                   0700
#endif
                  ) < 0)
    {
        rc_debug (RC_DEBUG_LEVEL_WARNING, "Unable to create %s", SOCKET_PATH);
        return -1;
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_UNIX;
    snprintf (servaddr.sun_path, sizeof (servaddr.sun_path),
              SOCKET_PATH"/rcd");
    
    if (bind (sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Unable to bind to domain socket");
        return -1;
    }

#ifdef HAVE_SO_PEERCRED
    chmod (servaddr.sun_path, 0777);
#endif

    if (listen (sockfd, 10) < 0) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Unable to listen to domain socket");
        return -1;
    }

    rcd_shutdown_add_handler (shutdown_server_cb, GINT_TO_POINTER (sockfd));

    iochannel = g_io_channel_unix_new(sockfd);
    g_io_add_watch(iochannel, G_IO_IN, conn_accept, callback);
    g_io_channel_unref(iochannel);

    return 0;
} /* rcd_unix_server_run_async */

