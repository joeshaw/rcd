/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * you-util.h
 *
 * Copyright (C) 2004 Novell, Inc.
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

#ifndef __YOU_UTIL__
#define __YOU_UTIL__

#include <xmlrpc.h>
#include <rc-channel.h>
#include "rc-you-patch.h"
#include "rc-world-you.h"

#define TMP_YOU_PATH_PREFIX "/tmp/lib"
#define TMP_YOU_PATH TMP_YOU_PATH_PREFIX "/YaST2/you/mnt"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

xmlrpc_value *rc_you_patch_to_xmlrpc             (RCYouPatch *patch,
                                                  xmlrpc_env *env);
xmlrpc_value *rc_you_patch_slist_to_xmlrpc_array (RCYouPatchSList *list,
                                                  xmlrpc_env *env);

#define RC_YOU_PATCH_FROM_XMLRPC_PATCH 1 << 0
    
RCYouPatch *rc_xmlrpc_to_rc_you_patch                  (xmlrpc_value *value,
                                                        xmlrpc_env   *env,
                                                        int           flags);
RCYouPatchSList *rc_xmlrpc_array_to_rc_you_patch_slist (xmlrpc_value *value,
                                                        xmlrpc_env   *env,
                                                        int           flags);

void create_you_directory_structure (RCYouPatchSList *patches, GError **error);
void clean_you_directory_structure  (void);

/* SAX Parser */
typedef struct _RCYouPatchSAXContext      RCYouPatchSAXContext;

RCYouPatchSAXContext *rc_you_patch_sax_context_new (RCChannel *channel);
void rc_you_patch_sax_context_parse_chunk (RCYouPatchSAXContext *ctx,
                                           const char *xmlbuf,
                                           int size);
RCYouPatchSList *rc_you_patch_sax_context_done (RCYouPatchSAXContext *ctx);

gint rc_extract_patches_from_helix_buffer (const guint8 *data, int len,
                                           RCChannel *channel,
                                           RCPatchFn callback,
                                           gpointer user_data);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /*__YOU_UTIL__ */
