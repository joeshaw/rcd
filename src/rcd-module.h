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

#endif /* __RCD_MODULE_H__ */
