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
rcd_autopull_resolve (RCDAutopull *pull)
{
    RCResolver *resolver;

    g_return_if_fail (pull != NULL);

    resolver = rc_resolver_new ();

    rc_resolver_add_packages_to_install_from_slist (resolver,
                                                    pull->all_to_add);

    rc_resolver_add_packages_to_remove_from_slist (resolver,
                                                   pull->all_to_subtract);

    rc_resolver_resolve_dependencies (resolver);

    /* FIXME: do something */

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
    rcd_autopull_resolve (pull);

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
channel_from_xml_node (xmlNode *node)
{
    RCWorld *world;
    RCChannel *channel = NULL;
    char *bid_str = NULL;
    guint32 bid;

    if (g_strcasecmp (node->name, "channel"))
        goto finished;
    
    bid_str = xml_get_prop (node, "bid");
    if (bid_str == NULL) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Ignoring channel tag without base ID.");
        goto finished;
    }

    bid = atol (bid_str);
    world = rc_get_world ();

    channel = rc_world_get_channel_by_base_id (world, bid);
    if (channel == NULL) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Unknown channel base ID '%s' in channel tag.", bid_str);
        goto finished;
    }

 finished:
    g_free (bid_str);

    return channel;
}

static RCPackage *
package_from_xml_node (xmlNode *node)
{
    RCWorld *world;
    RCPackage *pkg = NULL;
    char *bid_str = NULL;
    guint32 bid;
    char *pkg_name = NULL;
    RCChannel *channel;

    if (g_strcasecmp (node->name, "package"))
        goto finished;

    bid_str = xml_get_prop (node, "bid");
    if (bid_str == NULL) {
        /* FIXME: a better warning would be nice */
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Ignoring package tag without channel base ID.");
        goto finished;
    }

    bid = atol (bid_str);

    world = rc_get_world ();

    channel = rc_world_get_channel_by_base_id (world, bid);
    if (channel == NULL) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Unknown channel base ID '%s' in package tag.", bid_str);
        goto finished;
    }

    pkg_name = xml_get_content (node);

    pkg = rc_world_get_package (world, channel, pkg_name);

    if (pkg == NULL) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Can't find package '%s' in channel '%s'.",
                  pkg_name, rc_channel_get_name (channel));
    }

 finished:
    g_free (bid_str);
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
                pull->packages_to_update =
                    g_slist_prepend (pull->packages_to_update,
                                     rc_package_ref (package));
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

    for (node = node->xmlChildrenNode; node != NULL; node = node->next) {
        if (! g_strcasecmp (node->name, "session")) {
            RCDAutopull *pull = autopull_from_session_xml_node (node);
            if (pull)
                rcd_recurring_add ((RCDRecurring *) pull);
        }
    }
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

    /* FIXME: We should actually do something. */
}
