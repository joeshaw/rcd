/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-module.h
 *
 * Copyright (C) 2002 Ximian, Inc.
 *
 */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License, version 2,
 * as published by the Free Software Foundation.
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

#ifndef __RCD_MODULE_H__
#define __RCD_MODULE_H__

#include <gmodule.h>

/*
 * The current rcd module interface versions.  Any time the rcd's public API
 * changes, the major number will be incremented and the minor number reset
 * to zero.  Any time the rcd's public API is added to, the minor number
 * will be incremented.  Modules must expose a "rcd_module_major_version"
 * symbol which matches the major version.  Modules may expose a
 * "rcd_module_minor_version" symbol which must be less than or equal to
 * the minor version.
 */
#define RCD_MODULE_MAJOR_VERSION 3
#define RCD_MODULE_MINOR_VERSION 0

typedef struct _RCDModule RCDModule;

typedef void (*RCDModuleLoadFunc)(RCDModule *module);

struct _RCDModule {
    GModule *g_module;

    const char *name;
    const char *description;
    
    /* Mostly for informational purposes */
    const char *version;

    /*
     * interface_major should be incremented whenever an exported interface
     * is changed or removed.  That is, backward compatibility is broken.
     * interface_minor should also be reset to 0 when this happens.
     *
     * interface_minor should be incremented whenever an exported interface
     * is added.
     */

    int interface_major;
    int interface_minor;
};

/* Loads the modules */
void rcd_module_init (void);

/* Query to see if a module is on this system */
gboolean rcd_module_query (const char *name,
                           int         required_major,
                           int         required_minor);

/* FIXME: Wish this weren't basically a cut-and-paste from libredcarpet. */
typedef enum {
    RCD_DEBUG_LEVEL_ALWAYS   = -1,
    RCD_DEBUG_LEVEL_NONE     = 0,
    RCD_DEBUG_LEVEL_ERROR    = 1,
    RCD_DEBUG_LEVEL_CRITICAL = 2,
    RCD_DEBUG_LEVEL_WARNING  = 3,
    RCD_DEBUG_LEVEL_MESSAGE  = 4,
    RCD_DEBUG_LEVEL_INFO     = 5,
    RCD_DEBUG_LEVEL_DEBUG    = 6,
} RCDDebugLevel;

/* Syslog/debug output */
void rcd_module_debug (RCDDebugLevel  level,
                       RCDModule     *module,
                       const char    *format,
                       ...);

#endif /* __RCD_MODULE_H__ */
