/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <glib.h>

#include "rcd-module.h"

/* List of RCDModules */
static GSList *registered_modules = NULL;

static RCDModule *
load_module(const char *file_name)
{
    GModule *module;
    RCDModuleLoadFunc module_load_func;
    RCDModule *rcd_module;

    module = g_module_open(file_name, G_MODULE_BIND_LAZY);
    if (!module) {
        g_warning("Couldn't load module %s: %s", file_name, g_module_error());
        
        return NULL;
    }

    g_module_symbol(
        module, "rcd_module_load", (gpointer *) &module_load_func);
    if (!module_load_func) {
        g_warning("Couldn't load module %s: %s", file_name, g_module_error());
        g_module_close(module);
        return NULL;
    }

    printf("[%d]: Loaded module %s\n", getpid(), file_name);

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

    printf("[%d]: Initializing modules system\n", getpid());

    if (!g_module_supported()) {
        g_warning("Modules are not supported on this platform");
        return;
    }

    dir = g_dir_open(MODULEDIR, 0, NULL);
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
} /* rcd_module_init */
    
gboolean
rcd_module_query(const char *name)
{
    GSList *i;

    g_return_val_if_fail(name, FALSE);

    for (i = registered_modules; i; i = i->next) {
        RCDModule *module = i->data;

        if (!strcmp(module->name, name))
            return TRUE;
    }

    return FALSE;
} /* rcd_module_query */
