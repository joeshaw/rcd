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

static char *
get_mid (void)
{
    RCBuffer *buf;
    char *mid;

    buf = rc_buffer_map_file (SYSCONFDIR "/mcookie");
    if (!buf)
        return NULL;

    mid = g_strndup (buf->data, 36);
    mid[36] = '\0';

    rc_buffer_unmap_file (buf);

    return mid;
} /* get_mid */

static char *
get_secret (void)
{
    RCBuffer *buf;
    char *secret;

    buf = rc_buffer_map_file (SYSCONFDIR "/partnernet");
    if (!buf)
        return NULL;

    secret = g_strndup (buf->data, 36);
    secret[36] = '\0';

    rc_buffer_unmap_file (buf);

    return secret;
} /* get_secret */

static SoupUri *
get_premium_uri (const char *url)
{
    SoupUri *uri;

    uri = soup_uri_new (url);

    /* An invalid URL was passed to us */
    if (!uri)
        return NULL;

    uri->user = get_mid ();
    uri->passwd = get_secret ();

    return uri;
} /* get_premium_uri */

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
    xmlNewTextChild(pkgnode, NULL, "name", new_pkg->spec.name);
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
    char *mid = get_mid ();
    time_t curtime = time (NULL);
    RCDistroType *dt = rc_figure_distro ();
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
        dt->pretend_name ? dt->pretend_name : dt->unique_name);

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
transaction_sent_cb(SoupMessage *message, gpointer data)
{
    char **tid = data;
    const char *tid_string;

    if (SOUP_MESSAGE_IS_ERROR (message)) {
        g_warning ("An error was returned from the logging server: %d (%s)",
                   message->errorcode,
                   soup_error_get_phrase (message->errorcode));
        goto cleanup;
    }

    tid_string = soup_message_get_header (message->response_headers, "X-TID");

    if (tid_string) {
        *tid = g_strdup (tid_string);
        rc_debug (RC_DEBUG_LEVEL_DEBUG, "Got TID: \"%s\"", *tid);

    }
    else
        g_warning("No X-TID response");

cleanup:
    /* Not a g_free() because this is an xmlChar * */
    if (message->request.body)
        free (message->request.body);
} /* transaction_sent_cb */

void
rcd_transact_log_send_transaction (RCPackageSList  *install_packages,
                                   RCPackageSList  *remove_packages,
                                   char           **tid)
{
    xmlChar *xml_string;
    int bytes;
    char *url;
    SoupUri *soup_uri;
    SoupContext *context;
    SoupMessage *message;
    
    xml_string = transaction_xml (install_packages, remove_packages, &bytes);
    url = g_strdup_printf ("%s/log.php", rcd_prefs_get_host ());
    soup_uri = get_premium_uri (url);

    if (!soup_uri) {
        rc_debug (RC_DEBUG_LEVEL_WARNING, "Invalid log URL: %s", url);
        g_free (url);
        return;
    }

    context = soup_context_from_uri (soup_uri);
    g_free (url);

    message = soup_message_new_full (
        context, NULL, SOUP_BUFFER_USER_OWNED, xml_string, bytes);

    if (rcd_prefs_get_http10_enabled ())
        soup_message_set_http_version (message, SOUP_HTTP_1_0);

    soup_context_unref (context);
    soup_uri_free (soup_uri);

    soup_message_queue (message, transaction_sent_cb, tid);
} /* rcd_transact_log_send_transaction */

static xmlChar *
success_xml(char *tid, gboolean successful, char *message, int *bytes)
{
    xmlDoc *doc;
    xmlNode *root;
    xmlChar *xml_string;
    gchar *tmp;
    time_t curtime = time (NULL);
    char *mid = get_mid ();

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
success_sent_cb(SoupMessage *message, gpointer data)
{
    char *tid = data;

    rc_debug (RC_DEBUG_LEVEL_DEBUG, "Sent response for tid %s", tid);

    g_free (tid);

    /* Not a g_free() because it's an xmlChar * */
    if (message->request.body)
        free (message->request.body);
} /* transaction_sent_cb */

void
rcd_transact_log_send_success (char *tid, gboolean successful, char *msg)
{
    xmlChar *xml_string;
    int bytes;
    char *url;
    SoupUri *soup_uri;
    SoupContext *context;
    SoupMessage *message;

    if (!tid) {
        /* There's no tid available, so we can't send a success code */
        return;
    }

    xml_string = success_xml(tid, successful, msg, &bytes);
    url = g_strdup_printf ("%s/log.php", rcd_prefs_get_host ());
    soup_uri = get_premium_uri (url);

    if (!soup_uri) {
        rc_debug (RC_DEBUG_LEVEL_WARNING, "Invalid log URL: %s", url);
        g_free (url);
        return;
    }

    context = soup_context_from_uri (soup_uri);
    g_free (url);

    message = soup_message_new_full (
        context, NULL, SOUP_BUFFER_USER_OWNED, xml_string, bytes);

    if (rcd_prefs_get_http10_enabled ())
        soup_message_set_http_version (message, SOUP_HTTP_1_0);

    soup_context_unref (context);
    soup_uri_free (soup_uri);

    soup_message_queue (message, success_sent_cb, tid);
} /* rcd_transact_log_send_success */
