/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#ifndef __RCD_RPC_H__
#define __RCD_RPC_H__

#include <glib.h>
#include <xmlrpc.h>

#include "rcd-auth.h"

typedef struct {
    const char *host;

    RCDIdentity *identity;
} RCDRPCMethodData;

RCDRPCMethodData *rcd_rpc_get_method_data (void);

int rcd_rpc_register_method (const char        *method_name,
                             xmlrpc_method      method,
                             RCDAuthActionList *required_privileges,
                             gpointer           user_data);

/* Begins the RPC server thread */
void rcd_rpc_init (void);

#endif /* __RCD_RPC_H__ */
