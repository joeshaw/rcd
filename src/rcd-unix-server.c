/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "rcd-unix-server.h"

typedef struct {
    GByteArray *data;

    RCDUnixServerCallback cb;
} ConnectionState;

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

static gboolean
read_data(GIOChannel *iochannel,
          GIOCondition condition,
          gpointer user_data)
{
    ConnectionState *state = user_data;
    GIOError err;
    char read_buf[4096];
    int bytes_read = 0;
    int total_read = 0;
    GByteArray *result;
    int bytes_written;
    int total_written = 0;

    printf("Reading data!\n");

    err = g_io_channel_read (iochannel,
                             read_buf,
                             sizeof (read_buf),
                             &bytes_read);

    if (bytes_read) {
        g_byte_array_append(state->data, read_buf, bytes_read);
        total_read += bytes_read;
    }

    if (err == G_IO_ERROR_AGAIN) {
            return TRUE;
    }
    
    if (err != G_IO_ERROR_NONE) {
        printf("Error occurred\n");

        g_byte_array_free(state->data, TRUE);

        return FALSE;
    }

    if (substring_index(state->data->data, state->data->len, "\r\n\r\n") < 0)
        return TRUE;

    result = (state->cb) (state->data);

    if (!result)
        return FALSE;

    do {
        g_io_channel_write(iochannel, 
                           result->data + total_written,
                           result->len - total_written,
                           &bytes_written);
        
        total_written += bytes_written;
    } while (total_written < result->len);

    g_byte_array_free(result, TRUE);
    g_byte_array_free(state->data, TRUE);
    g_free(state);

    g_io_channel_close(iochannel);
    g_io_channel_unref(iochannel);

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
    ConnectionState *state;

    g_print ("[%d]: Accepting connection!\n", getpid());

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

    state = g_new0(ConnectionState, 1);
    state->data = g_byte_array_new();
    state->cb = (RCDUnixServerCallback) user_data;

    conn_chan = g_io_channel_unix_new (conn_fd);
    g_io_add_watch (conn_chan, 
                    G_IO_IN,
                    (GIOFunc) read_data,
                    state);

    return TRUE;
} /* conn_accept */

void
rcd_unix_server_run_async(RCDUnixServerCallback callback)
{
    int sockfd;
    struct sockaddr_un servaddr;
    GIOChannel *iochannel;

    g_return_if_fail(callback);

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        g_warning("Unable to open a domain socket");
        return;
    }

    unlink("/tmp/rcd");
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_UNIX;
    strcpy(servaddr.sun_path, "/tmp/rcd");
    
    bind(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
    listen(sockfd, 10);

    iochannel = g_io_channel_unix_new(sockfd);
    g_io_add_watch(iochannel, G_IO_IN, conn_accept, callback);
    g_io_channel_unref(iochannel);
} /* rcd_unix_server_run_async */
