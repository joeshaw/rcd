/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#ifndef __RCD_MODULE_H__
#define __RCD_MODULE_H__

#include <gmodule.h>

typedef struct _RCDModule RCDModule;

typedef void (*RCDModuleLoadFunc)(RCDModule *module);

struct _RCDModule {
    GModule *g_module;

    const char *name;
    const char *description;
};

/* Loads the modules */
void rcd_module_init(void);

/* Query to see if a module is on this system */
gboolean rcd_module_query(const char *name);

#endif /* __RCD_MODULE_H__ */
