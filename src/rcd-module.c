/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-module.c
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

#include <config.h>
#include "rcd-module.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <glib.h>

#include <libredcarpet.h>

/* List of RCDModules */
static GSList *registered_modules = NULL;

static RCDModule *
load_module(const char *file_name)
{
    GModule *module;
    RCDModuleLoadFunc module_load_func;
    RCDModule *rcd_module;
    int *major_module_version, *minor_module_version;

    module = g_module_open(file_name, G_MODULE_BIND_LAZY);
    if (!module) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Couldn't load module %s: %s", file_name, g_module_error());
        
        return NULL;
    }

    g_module_symbol (module, "rcd_module_major_version",
                     (gpointer *) &major_module_version);

    if (!major_module_version) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Can't load module %s: Missing major version info "
                  "(probably too old)", file_name);
        g_module_close (module);
        return NULL;
    }

    if (*major_module_version != RCD_MODULE_MAJOR_VERSION) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Can't load module %s: Module major version %d, %d is "
                  "required",
                  file_name, major_module_version, RCD_MODULE_MAJOR_VERSION);
        g_module_close (module);
        return NULL;
    }

    g_module_symbol (module, "rcd_module_minor_version",
                     (gpointer *) &minor_module_version);

    if (minor_module_version &&
        *minor_module_version > RCD_MODULE_MINOR_VERSION) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Can't load module %s: Module minor version %d, %d or "
                  "lower is required",
                  file_name, minor_module_version, RCD_MODULE_MINOR_VERSION);
        g_module_close (module);
        return NULL;
    }

    g_module_symbol (module, "rcd_module_load", 
                     (gpointer *) &module_load_func);

    if (!module_load_func) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Couldn't load module %s: %s", file_name, g_module_error());
        g_module_close(module);
        return NULL;
    }

    rc_debug (RC_DEBUG_LEVEL_INFO,
              "Loaded module %s", file_name);

    rcd_module = g_new0(RCDModule, 1);
    rcd_module->g_module = module;

    (*module_load_func)(rcd_module);

    return rcd_module;
} /* load_module */

void
rcd_module_init(void)
{
    GDir *dir;
    const char *file_name;

    if (!g_module_supported()) {
        rc_debug (RC_DEBUG_LEVEL_MESSAGE,
                  "Modules are not supported on this platform");
        return;
    }

    rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Initializing modules");

    dir = g_dir_open(MODULEDIR, 0, NULL);

    if (dir == NULL) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Could not find module directory "
                  MODULEDIR
                  " -- no modules loaded");
        return;
    }

    while ((file_name = g_dir_read_name(dir))) {
        if (strstr(file_name, ".so")) {
            char *f;
            RCDModule *module;

            f = g_build_path("/", MODULEDIR, file_name, NULL);
            module = load_module(f);
            g_free(f);

            if (module) {
                registered_modules = g_slist_prepend(
                    registered_modules, module);
            }

        }
    }

    g_dir_close (dir);
} /* rcd_module_init */
    
gboolean
rcd_module_query (const char *name, int required_major, int required_minor)
{
    GSList *i;

    g_return_val_if_fail(name, FALSE);

    for (i = registered_modules; i; i = i->next) {
        RCDModule *module = i->data;

        if (!strcmp (module->name, name)) {
            if (required_major < 0 ||
                (required_major == module->interface_major &&
                 required_minor <= module->interface_minor))
                return TRUE;
            else
                return FALSE;
        }
    }

    return FALSE;
} /* rcd_module_query */

void
rcd_module_debug (RCDDebugLevel  level,
                  RCDModule     *module,
                  const char    *format,
                  ...)
{
    va_list args;
    char *vp, *str;

    va_start (args, format);
    vp = g_strdup_vprintf (format, args);
    va_end (args);

    str = g_strdup_printf ("[%s] %s", module->name, vp);
    g_free (vp);

    rc_debug (level, str);

    g_free (str);
}
