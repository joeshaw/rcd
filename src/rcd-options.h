/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-options.h
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

#ifndef __RCD_OPTIONS_H__
#define __RCD_OPTIONS_H__

#include <glib.h>

void         rcd_options_parse                    (int argc,
                                                   const char **argv);

const char **rcd_options_get_argv                 (void);
const char  *rcd_options_get_config_file          (void);
gboolean     rcd_options_get_non_daemon_flag      (void);
gboolean     rcd_options_get_download_distro_flag (void);
gboolean     rcd_options_get_late_background      (void);
gboolean     rcd_options_get_non_root_flag        (void);
gboolean     rcd_options_get_no_network_flag      (void);
gboolean     rcd_options_get_no_modules_flag      (void);
const char  *rcd_options_get_bind_ipaddress       (void);
gboolean     rcd_options_get_remote_disable_flag  (void);
int          rcd_options_get_server_port          (void);
int          rcd_options_get_debug_level          (void);
int          rcd_options_get_syslog_level         (void);
const char  *rcd_options_get_dump_file            (void);
gboolean     rcd_options_get_show_version         (void);

void         rcd_options_reset_bind_ipaddress      (void);
void         rcd_options_reset_remote_disable_flag (void);
void         rcd_options_reset_server_port         (void);
void         rcd_options_reset_debug_level         (void);
void         rcd_options_reset_syslog_level        (void);

#endif /* __RCD_OPTIONS_H__ */

