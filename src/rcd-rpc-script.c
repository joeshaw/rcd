/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-rpc-script.c
 *
 * Copyright (C) 2003 Ximian, Inc.
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
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <xmlrpc.h>
#include <libredcarpet.h>

#include "rcd-module.h"
#include "rcd-rpc.h"


#define POLL_INTERVAL 500 /* half a second */

typedef struct {
    xmlrpc_env *env;
    gchar      *program_name;
	time_t      start_time;
	gint        timeout;

	gint        child_pid;
	gint        exit_status;

	GIOChannel *stdout_channel;
	GString    *stdout_str;
	GIOChannel *stderr_channel;
	GString    *stderr_str;
} RunnerData;

static void
runner_data_free (RunnerData *data)
{
    if (data->stdout_str)
        g_string_free (data->stdout_str, TRUE);
    if (data->stderr_str)
        g_string_free (data->stderr_str, TRUE);

    if (data->program_name) {
        unlink (data->program_name);
        g_free (data->program_name);
    }

	g_free (data);
}

static gboolean
runner_finished (RunnerData *data)
{
    /* FIXME: Report back to server (instead of printing) */

	if (WTERMSIG (data->exit_status))
		g_print ("Script timed out and was killed\n");
	else
		g_print ("status %d\n", data->exit_status);

	g_print ("stdout:\n%s\n", data->stdout_str->str);
	g_print ("stderr:\n%s\n", data->stderr_str->str);

	runner_data_free (data);

	return FALSE;
}

static gboolean
runner_read (GIOChannel *ioc, GIOCondition condition, gpointer data)
{
	gboolean retval = FALSE;
	gchar buf[1024];
	gsize len;
	GIOStatus io_status;
	RunnerData *rd = data;

try_read:
	io_status = g_io_channel_read_chars (ioc, buf, 1024, &len, NULL);

	switch (io_status) {
	case G_IO_STATUS_AGAIN:
		goto try_read;
		break;
	case G_IO_STATUS_NORMAL:
		retval = TRUE;
		break;
	default:
		break;
	}

	if (len > 0) {
		if (ioc == rd->stdout_channel)
			rd->stdout_str = g_string_append_len (rd->stdout_str, buf, len);
		else
			rd->stderr_str = g_string_append_len (rd->stderr_str, buf, len);
	}

	return retval;
}

static gboolean
runner_poll (RunnerData *data)
{
	int status, pid;
	time_t now;

	pid = waitpid (data->child_pid, &status, WNOHANG);
	if (pid > 0) {
		/* Finished */
		data->exit_status = status;
		g_idle_add ((GSourceFunc) runner_finished, data);
		return FALSE;
	}

	now = time (NULL);
	if ((now - data->start_time) >= data->timeout) {
		/* Timeout */
		if (kill (data->child_pid, SIGTERM) == -1)
			/* Die! */
			kill (data->child_pid, SIGKILL);
	}

	return TRUE;
}

static gboolean
runner (RunnerData *data)
{
	GError *error;
	gint child_pid;
	gint stdout_fd, stderr_fd;
	char *argv[] = {data->program_name, NULL};

	if (!g_spawn_async_with_pipes (NULL, /* Working directory */
                                   argv,
                                   NULL, /* env pointer */
                                   G_SPAWN_DO_NOT_REAP_CHILD, /* flags */
                                   NULL, /* child setup function */
                                   NULL, /* user data to function */
                                   &child_pid, /* child pid */
                                   NULL, /* stdin */
                                   &stdout_fd, /* stdout */
                                   &stderr_fd, /* stderr */
                                   &error)) {

        xmlrpc_env_set_fault (data->env, 1, error->message);
		g_error_free (error);
		return FALSE;
	}

	data->start_time = time (NULL);
	data->child_pid = child_pid;

	data->stdout_channel = g_io_channel_unix_new (stdout_fd);
	g_io_channel_set_flags (data->stdout_channel, G_IO_FLAG_NONBLOCK, NULL);
	data->stdout_str = g_string_new (NULL);

	data->stderr_channel = g_io_channel_unix_new (stderr_fd);
	g_io_channel_set_flags (data->stderr_channel, G_IO_FLAG_NONBLOCK, NULL);
	data->stderr_str = g_string_new (NULL);

	g_io_add_watch (data->stdout_channel, G_IO_IN | G_IO_HUP,
                    runner_read, data);
	g_io_channel_unref (data->stdout_channel);

	g_io_add_watch (data->stderr_channel, G_IO_IN | G_IO_HUP,
                    runner_read, data);
	g_io_channel_unref (data->stderr_channel);

	g_timeout_add (POLL_INTERVAL,
                   (GSourceFunc) runner_poll,
                   data);

    return TRUE;
}

static xmlrpc_value *
script_run (xmlrpc_env *env, xmlrpc_value *param_array, void *user_data)
{
    char *buf;
    char *file_name;
    size_t len;
    int fd, timeout;
    RunnerData *data;

    xmlrpc_parse_value (env, param_array, "(6i)", &buf, &len, &timeout);
    XMLRPC_FAIL_IF_FAULT (env);

    fd = g_file_open_tmp ("rcd-XXXXXX", &file_name, NULL);
    rc_write (fd, buf, len);
    rc_close (fd);

    chmod (file_name, S_IRUSR | S_IXUSR);

    data = g_new0 (RunnerData, 1);
    data->env = env;
    data->program_name = file_name;
    data->timeout = timeout;

    if (runner (data))
        return xmlrpc_build_value (env, "i", 1);
    else
        runner_data_free (data);

cleanup:
    return NULL;
} /* script_run */

void rcd_module_load (RCDModule *);

void
rcd_module_load (RCDModule *module)
{
    /* Initialize the module */
    module->name = "rcd.spawn";
    module->description = "A module to spawn processes";
    module->version = VERSION;
    module->interface_major = 1;
    module->interface_minor = 0;

    /* Register RPC methods */
    rcd_rpc_register_method ("rcd.spawn.run", script_run, "superuser", NULL);
} /* rcd_module_load */

int rcd_module_major_version = RCD_MODULE_MAJOR_VERSION;
int rcd_module_minor_version = RCD_MODULE_MINOR_VERSION;
