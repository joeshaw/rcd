/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <config.h>
#include "rcd-transfer-file.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#define BLOCK_SIZE 8192

static gboolean
file_read_data (GIOChannel   *iochannel,
                GIOCondition  condition,
                gpointer      user_data)
{
    RCDTransfer *t = user_data;
    RCDTransferProtocolFile *protocol = (RCDTransferProtocolFile *) t->protocol;
    GIOError err;
    char buf[BLOCK_SIZE];
    gsize bytes;

    if (!(condition & G_IO_IN))
        goto ERROR;

    err = g_io_channel_read (iochannel, buf, BLOCK_SIZE, &bytes);

    if (bytes)
        rcd_transfer_emit_data (t, buf, bytes);

    if (err == G_IO_ERROR_AGAIN)
        return TRUE;

    if (err != G_IO_ERROR_NONE)
        goto ERROR;

    if (bytes > 0) {
        /* More data to read.  Whee. */
        return TRUE;
    }
    else {
        /* No more bytes to read and no error condition; the file is done */
        g_io_channel_close (iochannel);
        rcd_transfer_emit_done (t);

        return FALSE;
    }

ERROR:
    g_source_remove (protocol->watch);
    
    rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_IO, NULL);
    rcd_transfer_emit_done (t);

    return FALSE;
}

static void
file_abort(RCDTransfer *t)
{
    RCDTransferProtocolFile *protocol = (RCDTransferProtocolFile *) t->protocol;

    g_source_remove (protocol->watch);

    rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_CANCELLED, NULL);
    rcd_transfer_emit_done (t);
} /* file_abort */

static int
file_open (RCDTransfer *t)
{
    SoupUri *uri = soup_uri_new (t->url);
    struct stat fdstat;
    int fd;
    GIOChannel *iochannel;
    RCDTransferProtocolFile *protocol;

    if (stat (uri->path, &fdstat)) {
        rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_FILE_NOT_FOUND, NULL);
        soup_uri_free (uri);
        return -1;
    }

    fd = open (uri->path, O_RDONLY);
    if (fd < 0) {
        rcd_transfer_set_error (t, RCD_TRANSFER_ERROR_IO,
                                "Couldn't open file for writing");
        soup_uri_free (uri);
        return -1;
    }

    t->file_size = fdstat.st_size;

    iochannel = g_io_channel_unix_new (fd);

    protocol = (RCDTransferProtocolFile *) t->protocol;
    protocol->watch = g_io_add_watch (
        iochannel,
        G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
        file_read_data,
        t);

    g_io_channel_unref (iochannel);

    soup_uri_free (uri);

    return 0;
} /* file_open */

char *
file_get_local_filename (RCDTransfer *t)
{
    /* Skip past the "file://" */
    return g_strdup (t->url + 7);
} /* file_get_local_filename */

RCDTransferProtocol *
rcd_transfer_protocol_file_new (void)
{
    RCDTransferProtocolFile *file_protocol;
    RCDTransferProtocol *protocol;

    file_protocol = g_new0 (RCDTransferProtocolFile, 1);
    protocol = (RCDTransferProtocol *) file_protocol;

    protocol->name = "file";

    protocol->get_local_filename_func = file_get_local_filename;
    protocol->open_func = file_open;
    protocol->abort_func = file_abort;

    return protocol;
}
