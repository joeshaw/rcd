/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include <glib.h>
#include <xmlrpc.h>

#ifndef __RCD_RPC_H__
#define __RCD_RPC_H__

int rcd_rpc_register_method (const char    *method_name,
                             xmlrpc_method  method,
                             gpointer       user_data);

/* Begins the RPC server thread */
void rcd_rpc_init (void);

#endif /* __RCD_RPC_H__ */
