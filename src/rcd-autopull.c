/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-autopull.c
 *
 * Copyright (C) 2002 Ximian, Inc.
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
#include <libredcarpet.h>

#include "rcd-module.h"
#include "rcd-recurring.h"
#include "rcd-transaction.h"
#include "rcd-transfer.h"
#include "rcd-prefs.h"

static RCDModule *rcd_module = NULL;

typedef struct _RCDAutopull RCDAutopull;

struct _RCDAutopull {
    RCDRecurring recurring;

    time_t first_pull;
    guint interval;

    GSList *channels_to_update;  /* update whole channel if possible */
    GSList *packages_to_update;  /* update if possible */
    GSList *packages_to_hold;    /* DON'T update */
    GSList *packages_to_install; /* extra installs */
    GSList *packages_to_remove;  /* extra removals */

    /* A place to store the total list of all to-be-added/subtracted
       packages */
    GSList *all_to_add;
    GSList *all_to_subtract;
};

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

#define AUTOPULL_CHECKIN_MIN     3600    /* 1 hours */
#define AUTOPULL_CHECKIN_MAX     172800  /* 48 hours */
#define AUTOPULL_CHECKIN_DEFAULT 7200    /* 2 hours */

static int autopull_checkin_interval = AUTOPULL_CHECKIN_DEFAULT;

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static void
updates_cb (RCPackage *old,
            RCPackage *nuevo,
            gpointer   user_data)
{
    RCDAutopull *pull = user_data;
    GSList *iter;

    /* Make sure this isn't an excluded package. */
    for (iter = pull->packages_to_hold; iter != NULL; iter = iter->next) {
        RCPackage *pkg = iter->data;
        if (rc_package_spec_equal (RC_PACKAGE_SPEC (pkg),
                                   RC_PACKAGE_SPEC (old)))
            return;
    }

    /* Check if this update is in the list of channels to update. */
    for (iter = pull->channels_to_update; iter != NULL; iter = iter->next) {
        RCChannel *channel = iter->data;
        if (rc_channel_get_id (channel) == rc_channel_get_id (nuevo->channel))
            goto update_me_harder;
    }

    /* Check if this update is in the list of packages to update. */
    for (iter = pull->packages_to_update; iter != NULL; iter = iter->next) {
        RCPackage *pkg = iter->data;
        if (rc_package_spec_equal (RC_PACKAGE_SPEC (pkg),
                                   RC_PACKAGE_SPEC (old)))
            goto update_me_harder;
    }

    return;

 update_me_harder:
    pull->all_to_add = g_slist_prepend (pull->all_to_add,
                                        rc_package_ref (nuevo));
}

static void
rcd_autopull_find_targets (RCDAutopull *pull)
{
    GSList *iter;

    g_return_if_fail (pull != NULL);

    if (pull->all_to_add) {
        rc_package_slist_unref (pull->all_to_add);
        g_slist_free (pull->all_to_add);
        pull->all_to_add = NULL;
    }

    if (pull->all_to_subtract) {
        rc_package_slist_unref (pull->all_to_subtract);
        g_slist_free (pull->all_to_subtract);
        pull->all_to_subtract = NULL;
    }

    for (iter = pull->packages_to_install; iter != NULL; iter = iter->next) {
        pull->all_to_add = g_slist_prepend (pull->all_to_add,
                                            rc_package_ref (iter->data));
    }

    for (iter = pull->packages_to_remove; iter != NULL; iter = iter->next) {
        pull->all_to_subtract = g_slist_prepend (pull->all_to_subtract,
                                                 rc_package_ref (iter->data));
    }

    rc_world_foreach_system_upgrade (rc_get_world (),
                                     updates_cb,
                                     pull);
}

static void
pkg_install (RCPackage *pkg, RCPackageStatus status, gpointer user_data)
{
    GSList **slist = user_data;

    if (rc_package_status_is_to_be_installed (status))
        *slist = g_slist_prepend (*slist,
                                  rc_package_ref (pkg));
}

static void
pkg_remove (RCPackage *pkg, RCPackageStatus status, gpointer user_data)
{
    GSList **slist = user_data;

    if (rc_package_status_is_to_be_uninstalled (status)
        && rc_package_is_installed (pkg))
        *slist = g_slist_prepend (*slist, 
                                  rc_package_ref (pkg));
}

static void
pkg_upgrade (RCPackage *pkg_new, RCPackageStatus status_new,
             RCPackage *pkg_old, RCPackageStatus status_old,
             gpointer user_data)
{
    GSList **slist = user_data;

    *slist = g_slist_prepend (*slist,
                              rc_package_ref (pkg_new));
}

static void
append_dep_info (RCResolverInfo *info, gpointer user_data)
{
    GString *dep_failure_info = user_data;
    gboolean debug = FALSE;

    if (getenv ("RCD_DEBUG_DEPS"))
        debug = TRUE;

    if (debug || rc_resolver_info_is_important (info)) {
        char *msg = rc_resolver_info_to_string (info);

        g_string_append_printf (
            dep_failure_info, "\n%s%s%s",
            (debug && rc_resolver_info_is_error (info)) ? "ERR " : "",
            (debug && rc_resolver_info_is_important (info)) ? "IMP " : "",
            msg);
        g_free (msg);
    }
} /* append_dep_info */
        
static char *
get_dep_failure_info (RCResolver *resolver)
{
    RCResolverQueue *queue;
    GString *dep_failure_info = g_string_new ("Unresolved dependencies:\n");
    char *str;

    /* FIXME: Choose a best invalid queue */
    queue = (RCResolverQueue *) resolver->invalid_queues->data;

    rc_resolver_context_foreach_info (queue->context, NULL, -1,
                                      append_dep_info, dep_failure_info);

    str = dep_failure_info->str;

    g_string_free (dep_failure_info, FALSE);

    return str;
} /* get_dep_failure_info */

static void
rcd_autopull_resolve_and_transact (RCDAutopull *pull)
{
    RCResolver *resolver;
    GSList *to_install = NULL;
    GSList *to_remove = NULL;
    int tid;

    g_return_if_fail (pull != NULL);

    resolver = rc_resolver_new ();

    rc_resolver_add_packages_to_install_from_slist (resolver,
                                                    pull->all_to_add);

    rc_resolver_add_packages_to_remove_from_slist (resolver,
                                                   pull->all_to_subtract);

    rc_resolver_resolve_dependencies (resolver);

    if (resolver->best_context == NULL) {
        char *dep_failure_info;

        rc_debug (RC_DEBUG_LEVEL_WARNING, "Resolution failed!");

        dep_failure_info = get_dep_failure_info (resolver);
        rcd_transaction_log_to_server (pull->all_to_add,
                                       pull->all_to_subtract,
                                       rcd_module->description,
                                       VERSION,
                                       FALSE,
                                       dep_failure_info);
        g_free (dep_failure_info);
                                       
        goto cleanup;
    }

    rc_resolver_context_foreach_install (resolver->best_context,
                                         pkg_install,
                                         &to_install);

    rc_resolver_context_foreach_uninstall (resolver->best_context,
                                           pkg_remove,
                                           &to_remove);

    rc_resolver_context_foreach_upgrade (resolver->best_context,
                                         pkg_upgrade,
                                         &to_install);

    if (to_install != NULL || to_remove != NULL) {
        GSList *iter;

        rc_debug (RC_DEBUG_LEVEL_INFO,
                  "Beginning Autopull");
        for (iter = to_install; iter != NULL; iter = iter->next) {
            rc_debug (RC_DEBUG_LEVEL_INFO,
                      "  Install: %s",
                      rc_package_to_str_static (iter->data));
        }
        for (iter = to_remove; iter != NULL; iter = iter->next) {
            rc_debug (RC_DEBUG_LEVEL_INFO,
                      "   Remove: %s",
                      rc_package_to_str_static (iter->data));
        }

        tid = rcd_transaction_begin (rc_get_world (),
                                     to_install,
                                     to_remove,
                                     FALSE,
                                     rcd_module->description,
                                     VERSION,
                                     "localhost",
                                     "autopull " VERSION);

    } else {
        rc_debug (RC_DEBUG_LEVEL_INFO,
                  "Autopull: no action necessary.");
    }

    /* FIXME: Do we want to use the transaction ID for anything? */

 cleanup:
    rc_package_slist_unref (to_install);
    rc_package_slist_unref (to_remove);
    rc_resolver_free (resolver);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static void
ap_rec_destroy (RCDRecurring *rec)
{
    RCDAutopull *pull = (RCDAutopull *) rec;

    g_slist_foreach (pull->channels_to_update,
                     (GFunc) rc_channel_unref,
                     NULL);

    rc_package_slist_unref (pull->packages_to_update);
    g_slist_free (pull->packages_to_update);

    rc_package_slist_unref (pull->packages_to_hold);
    g_slist_free (pull->packages_to_hold);

    rc_package_slist_unref (pull->all_to_add);
    g_slist_free (pull->all_to_add);

    rc_package_slist_unref (pull->all_to_subtract);
    g_slist_free (pull->all_to_subtract);
}

static void
ap_rec_execute (RCDRecurring *rec)
{
    RCDAutopull *pull = (RCDAutopull *) rec;

    rcd_autopull_find_targets (pull);
    rcd_autopull_resolve_and_transact (pull);
}

static time_t
ap_rec_first (RCDRecurring *rec, time_t now)
{
    RCDAutopull *pull = (RCDAutopull *) rec;
    time_t first = pull->first_pull;
    int adjust;
    
    /* If the first pull time is in the past, compute (using the
       interval) the next pull time that is in the future. */
    if (first != 0 && first < now) {
        
        /* If the interval is 0, return 0 (which is a code for
           "do this operation right now") */
        if (pull->interval == 0)
            return 0;

        adjust = ((now - first) % pull->interval == 0) ? 0 : 1;
        first += ((now - first) / pull->interval + adjust) * pull->interval;
    }

    return first;
}

static time_t
ap_rec_next (RCDRecurring *rec, time_t previous)
{
    RCDAutopull *pull = (RCDAutopull *) rec;

    if (pull->interval > 0)
        return previous + pull->interval;

    /* 0 == never do this action again */
    return 0; 
}

static RCDAutopull *
rcd_autopull_new (time_t first_pull, guint interval)
{
    RCDAutopull *pull;

    pull = g_new0 (RCDAutopull, 1);

    pull->recurring.tag = g_quark_from_static_string ("autopull");
    
    pull->recurring.destroy = ap_rec_destroy;
    pull->recurring.execute = ap_rec_execute;
    pull->recurring.first   = ap_rec_first;
    pull->recurring.next    = ap_rec_next;

    pull->first_pull         = first_pull;
    pull->interval           = interval;
    pull->channels_to_update = NULL;
    pull->packages_to_update = NULL;
    pull->packages_to_hold   = NULL;

    return pull;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

/*
  Our autopull XML looks like this:

<autopull>
  <session>
    <starttime>1029775674</starttime>
    <interval>7200</interval>
    <channel bid="2" />
    <channel bid="20769" />
    <package bid="418" name="evolution" />
    <package bid="20769" name="perl" />
  </session>
  <session>
    <starttime>1029775000</starttime>
    <interval>0</interval>
    <package bid="20769" name="evolution" />
    <package name="python" />
    <package name="libgal19" remove="1" />
  </session>
  <session>
    <starttime>0</starttime>
    <interval>0</interval>
    <package bid="598" name="kernel-utils" />
  </session>
</autopull>
*/

static RCChannel *
channel_from_xml_props (xmlNode *node)
{
    RCWorld *world;
    RCChannel *channel = NULL;
    char *alias_str = NULL;
    char *cid_str = NULL;
    char *bid_str = NULL;

    world = rc_get_world ();

    alias_str = xml_get_prop (node, "alias");
    if (alias_str) {
        rc_debug (RC_DEBUG_LEVEL_INFO,
                  "Looking for channel with alias='%s'",
                  alias_str);
        channel = rc_world_get_channel_by_alias (world, alias_str);
        if (channel)
            goto finished;
    }

    cid_str = xml_get_prop (node, "cid");
    if (cid_str) {
        guint32 cid = 0;
        cid = atol (cid_str);
        rc_debug (RC_DEBUG_LEVEL_INFO,
                  "Looking for channel with cid=%d ('%s')",
                  cid, cid_str);
        if (cid) {
            channel = rc_world_get_channel_by_id (world, cid);
            if (channel)
                goto finished;
        }
    }
    
    bid_str = xml_get_prop (node, "bid");
    if (bid_str) {
        guint32 bid = 0;
        rc_debug (RC_DEBUG_LEVEL_INFO,
                  "Looking for channel with bid=%d ('%s')",
                  bid, bid_str);
        bid = atol (bid_str);
        if (bid) {
            channel = rc_world_get_channel_by_base_id (world, bid);
            if (channel)
                goto finished;
        }
    }

 finished:
    g_free (alias_str);
    g_free (bid_str);
    g_free (cid_str);

    return channel;
}


static RCChannel *
channel_from_xml_node (xmlNode *node)
{
    RCChannel *channel = NULL;
    
    if (! g_strcasecmp (node->name, "channel"))
        channel = channel_from_xml_props (node);

    if (channel == NULL) {
        /* Wow... what a bad error message. */
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "No valid channel specified in channel tag!");
    }

    return channel;
}

static RCPackage *
package_from_xml_node (xmlNode *node)
{
    RCWorld *world;
    RCPackage *pkg = NULL;
    char *pkg_name = NULL;
    RCChannel *channel;

    if (g_strcasecmp (node->name, "package"))
        goto finished;

    channel = channel_from_xml_props (node);

    /* If the channel comes back NULL, we will treat this as a
       system package. */

    world = rc_get_world ();

    pkg_name = xml_get_prop (node, "name");

    pkg = rc_world_get_package (world,
                                channel ? channel : RC_WORLD_SYSTEM_PACKAGES,
                                pkg_name);

    if (pkg == NULL) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Can't find package '%s' in channel '%s'.",
                  pkg_name,
                  channel ? rc_channel_get_name (channel) : "SYSTEM");
    }

    g_print ("%s\n", rc_package_to_str_static (pkg));

 finished:
    g_free (pkg_name);

    return pkg;
}

static RCDAutopull *
autopull_from_session_xml_node (xmlNode *node)
{
    RCDAutopull *pull = NULL;
    char *starttime_str = NULL;
    char *interval_str = NULL;
    
    if (g_strcasecmp (node->name, "session"))
        return NULL;

    for (node = node->xmlChildrenNode; node != NULL; node = node->next) {

        if (! g_strcasecmp (node->name, "starttime")) {

            if (starttime_str == NULL)
                starttime_str = xml_get_content (node);
            else
                rc_debug (RC_DEBUG_LEVEL_WARNING,
                          "Extra starttime tag ignored.");

        } else if (! g_strcasecmp (node->name, "interval")) {

            if (interval_str == NULL)
                interval_str = xml_get_content (node);
            else
                rc_debug (RC_DEBUG_LEVEL_WARNING,
                          "Extra interval tag ignored.");
            
        } else if (! g_strcasecmp (node->name, "channel")) {
            
            RCChannel *channel = channel_from_xml_node (node);

            if (channel) {
                g_assert (pull != NULL);
                pull->channels_to_update =
                    g_slist_prepend (pull->channels_to_update,
                                     rc_channel_ref (channel));
            }

        } else if (! g_strcasecmp (node->name, "package")) {

            RCPackage *package = package_from_xml_node (node);
            
            if (package) {
                g_assert (pull != NULL);

                /* 
                   If the XML specified a system package (by omitting
                   any channel info, thus causing us to find the package
                   in the system instead of in a specific channel),
                   we will just try to update the package from
                   any subscribed channel.

                   Otherwise, we will try to install the package
                   out of the specified channel.  If that package is
                   already installed, the install will (of course)
                   be turned into a no-op by the dependency resolver.
                */

                if (rc_package_is_installed (package)) {
                    pull->packages_to_update =
                        g_slist_prepend (pull->packages_to_update,
                                         rc_package_ref (package));
                } else {
                    pull->packages_to_install =
                        g_slist_prepend (pull->packages_to_install,
                                         rc_package_ref (package));
                }
            }
        }

        /* Construct our pull object after we have the starttime
           and interval. */
        if (starttime_str != NULL && interval_str != NULL && pull == NULL) {
            time_t starttime;
            guint32 interval;
            
            starttime = (time_t) atol (starttime_str);
            interval = atol (interval_str);

            pull = rcd_autopull_new (starttime, interval);
        }
    }

    g_free (starttime_str);
    g_free (interval_str);

    return pull;
}

static void
rcd_autopull_process_xml (xmlNode *node)
{
    g_return_if_fail (node != NULL);

    if (g_strcasecmp (node->name, "autopull")) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "This doesn't look like autopull XML!");
        return;
    }

    /* We reset the check-in interval to the default every time. */
    autopull_checkin_interval = AUTOPULL_CHECKIN_DEFAULT;

    for (node = node->xmlChildrenNode; node != NULL; node = node->next) {

        if (! g_strcasecmp (node->name, "checkin_interval")) {

            char *ci_str = xml_get_content (node);

            if (ci_str && *ci_str) {
                autopull_checkin_interval = atoi (ci_str);
                
                /* Make sure that the check-in interval doesn't get
                   set to some strange, extreme value. */
                if (autopull_checkin_interval <= 0)
                    autopull_checkin_interval = AUTOPULL_CHECKIN_DEFAULT;
                else if (autopull_checkin_interval < AUTOPULL_CHECKIN_MIN)
                    autopull_checkin_interval = AUTOPULL_CHECKIN_MIN;
                else if (autopull_checkin_interval > AUTOPULL_CHECKIN_MAX)
                    autopull_checkin_interval = AUTOPULL_CHECKIN_MAX;
            }
            g_free (ci_str);

        } else if (! g_strcasecmp (node->name, "session")) {
        
            RCDAutopull *pull = autopull_from_session_xml_node (node);
            
            if (pull)
                rcd_recurring_add ((RCDRecurring *) pull);
        }
    }
}

static void
rcd_autopull_get_xml_from_file (const char *filename)
{
    xmlDoc *doc;

    if (! g_file_test (filename, G_FILE_TEST_EXISTS)) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "File '%s' doesn't exist; can't get autopull XML",
                  filename);
        return;
    }

    doc = xmlParseFile (filename);
    if (doc == NULL) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Can't parse autopull XML in file '%s'",
                  filename);
        return;
    }

    /* Remove any existing recurring autopull items. */
    rcd_recurring_foreach (g_quark_from_static_string ("autopull"),
                           (RCDRecurringFn) rcd_recurring_remove,
                           NULL);

    rcd_autopull_process_xml (xmlDocGetRootElement (doc));

    xmlFreeDoc (doc);
}

static void
rcd_autopull_download_xml (void)
{
    RCDTransfer *t = NULL;
    char *url = NULL;
    GByteArray *data = NULL;
    xmlDoc *doc = NULL;

    /* Disable autopull if we aren't in premium mode. */
    if (! rcd_prefs_get_premium ())
        return;

    url = g_strdup_printf ("%s/autopull.php",
                           rcd_prefs_get_host ());

    t = rcd_transfer_new (url, 0, NULL);
    data = rcd_transfer_begin_blocking (t);
    
    if (rcd_transfer_get_error (t)) {
        rc_debug (RC_DEBUG_LEVEL_ERROR,
                  "Attempt to download autopull data failed: %s",
                  rcd_transfer_get_error_string (t));
        goto cleanup;
    }

    doc = rc_uncompress_xml (data->data, data->len);
    if (doc == NULL) {
        rc_debug (RC_DEBUG_LEVEL_ERROR,
                  "Unable to uncompress or parse autopull data.");
        goto cleanup;
    }

    /* Remove any existing recurring autopull items. */
    rcd_recurring_foreach (g_quark_from_static_string ("autopull"),
                           (RCDRecurringFn) rcd_recurring_remove,
                           NULL);

    rcd_autopull_process_xml (xmlDocGetRootElement (doc));

 cleanup:

    g_free (url);

    if (t)
        g_object_unref (t);

    if (data)
        g_byte_array_free (data, TRUE);

    if (doc)
        xmlFreeDoc (doc);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

/* A recurring event to download/refresh the autopull information. */

static RCDRecurring autopull_xml_fetch;

static void
xml_fetch_execute (RCDRecurring *recur)
{
    const char *file_override;

    file_override = getenv ("RCD_AUTOPULL_XML_FROM_FILE");

    if (file_override) {

        rc_debug (RC_DEBUG_LEVEL_INFO,
                  "Loading autopull XML from '%s'",
                  file_override);

        rcd_autopull_get_xml_from_file (file_override);

    } else {

        rc_debug (RC_DEBUG_LEVEL_INFO,
                  "Downloading autopull XML");

        rcd_autopull_download_xml ();
    }
}

time_t
xml_fetch_first (RCDRecurring *recur, time_t now)
{
    /* We do our first download of the autopull XML in 60 seconds.
       This allows other modules to load and gives the system time to
       "settle" before we start autopulling. */
    /* FIXME: Is this really what we want to do? */
    return now + 60;
}

time_t
xml_fetch_next (RCDRecurring *recur, time_t previous)
{
    return previous + autopull_checkin_interval;
}

static void
recurring_autopull_xml_fetch_init (void)
{
    autopull_xml_fetch.tag     = g_quark_from_static_string ("autopull-xml");
    autopull_xml_fetch.destroy = NULL;
    autopull_xml_fetch.execute = xml_fetch_execute;
    autopull_xml_fetch.first   = xml_fetch_first;
    autopull_xml_fetch.next    = xml_fetch_next;

    rcd_recurring_add (&autopull_xml_fetch);
}


/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

/* We put a prototype here to keep the compiler from complaining. */
void rcd_module_load (RCDModule *);

void
rcd_module_load (RCDModule *module)
{
    /* Initialize the module */
    module->name = "rcd.autopull";
    module->description = "Autopull";
    module->version = VERSION;
    module->interface_major = 0;
    module->interface_minor = 0;

    rcd_module = module;

    recurring_autopull_xml_fetch_init ();
}
