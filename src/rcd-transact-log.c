/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * rcd-transact-log.c
 *
 * Copyright (C) 2000-2002 Ximian, Inc.
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
#include "rcd-transact-log.h"

#include <libsoup/soup.h>
#include <libxml/tree.h>

#include "rcd-prefs.h"
#include "rcd-transfer.h"
#include "rcd-transfer-http.h"

typedef enum {
    MANIFEST_UPDATE,
    MANIFEST_INSTALL,
    MANIFEST_REMOVE
} ManifestAction;

static xmlNode *
manifest_xml_node(int             cid,
                  RCPackage      *new_pkg,
                  RCPackage      *old_pkg,
                  ManifestAction  action)
{
    xmlNode *node, *pkgnode;
    char *tmp = NULL;

    node = xmlNewNode(NULL, "manifest");

    if (cid) {
        tmp = g_strdup_printf("%d", cid);
        xmlNewTextChild(node, NULL, "cid", tmp);
        g_free(tmp);
    }

    switch (action) {
    case MANIFEST_UPDATE:
        tmp = "update";
        break;
    case MANIFEST_INSTALL:
        tmp = "install";
        break;
    case MANIFEST_REMOVE:
        tmp = "remove";
        break;
    default:
        g_assert_not_reached();
        break;
    }
    xmlNewTextChild(node, NULL, "action", tmp);

    /* write info on the new package */
    pkgnode = xmlNewChild (node, NULL, "package", NULL);
    xmlNewTextChild(pkgnode, NULL, "name",
                    g_quark_to_string (new_pkg->spec.nameq));
    tmp = g_strdup_printf("%d", new_pkg->spec.epoch);
    xmlNewTextChild(pkgnode, NULL, "epoch", tmp);
    g_free(tmp);
    xmlNewTextChild(pkgnode, NULL, "version", new_pkg->spec.version);
    xmlNewTextChild(pkgnode, NULL, "release", new_pkg->spec.release);

    if (action != MANIFEST_REMOVE) {
        RCPackageUpdate *upd = rc_package_get_latest_update(new_pkg);

        if (upd) {
            tmp = g_strdup_printf("%d", upd->package_size);
            xmlNewTextChild(pkgnode, NULL, "size", tmp);
            g_free(tmp);

            tmp = g_strdup_printf("%d", upd->hid);
            xmlNewTextChild(pkgnode, NULL, "hid", tmp);
            g_free(tmp);

            if (new_pkg->channel) {
                tmp = g_strdup_printf ("%d",
                                       rc_channel_get_id (new_pkg->channel));
                xmlNewTextChild(pkgnode, NULL, "channel_id", tmp);
                g_free(tmp);
            }

            if (upd->package_url)
                xmlNewTextChild(pkgnode, NULL, "url", upd->package_url);
        }
    }

    /* write info on the old package, if any */
    if (old_pkg) {
        pkgnode = xmlNewChild (node, NULL, "oldpackage", NULL);
        tmp = g_strdup_printf("%d", old_pkg->spec.epoch);
        xmlNewTextChild(pkgnode, NULL, "epoch", tmp);
        g_free(tmp);
        xmlNewTextChild(pkgnode, NULL, "version", old_pkg->spec.version);
        xmlNewTextChild(pkgnode, NULL, "release", old_pkg->spec.release);
    }

    return node;
} /* manifest_xml_node */

static xmlChar *
transaction_xml (RCPackageSList *install_packages, 
                 RCPackageSList *remove_packages,
                 int            *bytes)
{
    xmlDoc *doc;
    xmlNode *root;
    const char *mid = rcd_prefs_get_mid ();
    time_t curtime = time (NULL);
    char *tmp;
    RCPackageSList *i;
    xmlChar *xml_string;

    doc = xmlNewDoc("1.0");
    root = xmlNewNode (NULL, "transaction");
    xmlDocSetRootElement (doc, root);

    xmlNewTextChild(root, NULL, "mid", mid);
    
    tmp = g_strdup_printf("%ld", curtime);
    xmlNewTextChild(root, NULL, "start_time", tmp);
    g_free(tmp);

    xmlNewTextChild(
        root, NULL, "distro",
        rc_distro_get_target ());

    i = install_packages;
    while (i) {
        RCPackage *p = i->data;
        RCPackage *sys_pkg;
        ManifestAction action;
        xmlNode *n;

        sys_pkg = rc_world_find_installed_version (rc_get_world (), p);

        if (sys_pkg)
            action = MANIFEST_UPDATE;
        else
            action = MANIFEST_INSTALL;

        n = manifest_xml_node (
            p->channel ? rc_channel_get_id (p->channel) : -1,
            p, sys_pkg, action);

        xmlAddChild(root, n);

        i = i->next;
    }

    i = remove_packages;
    while (i) {
        RCPackage *p = i->data;
        xmlNode *n;

        n = manifest_xml_node (0, p, NULL, MANIFEST_REMOVE);

        xmlAddChild(root, n);

        i = i->next;
    }

    xmlDocDumpMemory(doc, &xml_string, bytes);
            
    return xml_string;
} /* transaction_xml */

static void
transaction_sent (RCDTransfer *t, gpointer user_data)
{
    char **tid = user_data;
    RCDTransferProtocolHTTP *protocol;
    const char *tid_string;

    if (rcd_transfer_get_error (t)) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "An error occurred trying to get a TID: %s",
                  rcd_transfer_get_error_string (t));
        return;
    }

    g_assert (strcmp (t->protocol->name, "http") == 0);

    protocol = (RCDTransferProtocolHTTP *) t->protocol;

    tid_string = rcd_transfer_protocol_http_get_response_header (protocol, "X-TID");

    if (tid_string) {
        *tid = g_strdup (tid_string);
        rc_debug (RC_DEBUG_LEVEL_DEBUG, "Got TID: \"%s\"", *tid);

    }
    else
        g_warning("No X-TID response");

    /* Not a g_free() because this is an xmlChar * */
    free (protocol->request_body);

    g_object_unref (t);
} /* transaction_sent */

void
rcd_transact_log_send_transaction (RCPackageSList  *install_packages,
                                   RCPackageSList  *remove_packages,
                                   char           **tid)
{
    xmlChar *xml_string;
    int bytes;
    char *url;
    RCDTransfer *t;
    RCDTransferProtocolHTTP *protocol;
    
    url = g_strdup_printf ("%s/log.php", rcd_prefs_get_host ());

    t = rcd_transfer_new (url, 0, NULL);

    g_free (url);

    if (!t->protocol || strcmp (t->protocol->name, "http") != 0) {
        rc_debug (RC_DEBUG_LEVEL_WARNING, "Invalid log URL: %s", url);
        g_object_unref (t);
        return;
    }

    protocol = (RCDTransferProtocolHTTP *) t->protocol;

    rcd_transfer_protocol_http_set_method (protocol, SOUP_METHOD_POST);

    xml_string = transaction_xml (install_packages, remove_packages, &bytes);
    rcd_transfer_protocol_http_set_request_body (
        protocol, xml_string, bytes);

    g_signal_connect (t, "file_done", 
                      G_CALLBACK (transaction_sent), tid);

    rcd_transfer_begin (t);
} /* rcd_transact_log_send_transaction */

static xmlChar *
success_xml(const char *tid,
            gboolean    successful,
            const char *message,
            int        *bytes)
{
    xmlDoc *doc;
    xmlNode *root;
    xmlChar *xml_string;
    gchar *tmp;
    time_t curtime = time (NULL);
    const char *mid = rcd_prefs_get_mid ();

    doc = xmlNewDoc("1.0");
    root = xmlNewNode (NULL, "transaction_end");
    xmlDocSetRootElement (doc, root);

    xmlNewTextChild(root, NULL, "mid", mid);
    xmlNewTextChild(root, NULL, "tid", tid);
    xmlNewTextChild(root, NULL, "success", successful ? "1" : "0");

    tmp = g_strdup_printf("%ld", curtime);
    xmlNewTextChild(root, NULL, "end_time", tmp);
    g_free(tmp);

    if (message)
        xmlNewTextChild(root, NULL, "message", message);

    xmlDocDumpMemory(doc, &xml_string, bytes);
            
    return xml_string;
} /* success_xml */

static void
success_sent (RCDTransfer *t, gpointer user_data)
{
    char *tid = user_data;
    RCDTransferProtocolHTTP *protocol;

    if (rcd_transfer_get_error (t)) {
        rc_debug (RC_DEBUG_LEVEL_WARNING, 
                  "An error occurred trying to send success for TID '%s': %s",
                  tid, rcd_transfer_get_error_string (t));
        g_free (tid);
        return;
    }
    
    g_assert (strcmp (t->protocol->name, "http") == 0);

    protocol = (RCDTransferProtocolHTTP *) t->protocol;

    rc_debug (RC_DEBUG_LEVEL_DEBUG, "Sent response for tid %s", tid);

    g_free (tid);

    /* Not a g_free() because it's an xmlChar * */
    free (protocol->request_body);

    g_object_unref (t);
} /* success_sent */

void
rcd_transact_log_send_success (char       *tid,
                               gboolean    successful, 
                               const char *msg)
{
    xmlChar *xml_string;
    int bytes;
    char *url;
    RCDTransfer *t;
    RCDTransferProtocolHTTP *protocol;

    if (!tid) {
        /* There's no tid available, so we can't send a success code */
        return;
    }

    url = g_strdup_printf ("%s/log.php", rcd_prefs_get_host ());

    t = rcd_transfer_new (url, 0, NULL);

    g_free (url);

    if (!t->protocol || strcmp (t->protocol->name, "http") != 0) {
        rc_debug (RC_DEBUG_LEVEL_WARNING, "Invalid log URL: %s", url);
        g_object_unref (t);
        return;
    }

    protocol = (RCDTransferProtocolHTTP *) t->protocol;

    rcd_transfer_protocol_http_set_method (protocol, SOUP_METHOD_POST);

    xml_string = success_xml (tid, successful, msg, &bytes);
    rcd_transfer_protocol_http_set_request_body (
        protocol, xml_string, bytes);

    g_signal_connect (t, "file_done",
                      G_CALLBACK (success_sent), tid);

    rcd_transfer_begin (t);
} /* rcd_transact_log_send_success */
