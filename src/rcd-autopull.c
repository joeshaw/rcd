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

    GSList *channels_to_update;
    GSList *packages_to_update;
    GSList *packages_to_hold;
};

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
}

static void
ap_rec_execute (RCDRecurring *rec)
{
    RCDAutopull *pull = (RCDAutopull *) rec;
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

/* We are liberal and allow channels to be specified by ID, name
   or alias. */
static RCChannel *
channel_from_str (const char *str)
{
    RCWorld *world;
    RCChannel *channel;
    guint32 cid;

    if (str == NULL)
        return NULL;

    world = rc_get_world ();

    cid = atol (str);
    if (cid) {
        channel = rc_world_get_channel_by_id (world, cid);
    } else {
        channel = rc_world_get_channel_by_name (world, str);
        if (channel == NULL) {
            channel = rc_world_get_channel_by_alias (world, str);
        }
    }
    
    return channel;
}

static RCPackage *
package_from_xml_node (xmlNode *node)
{
    RCWorld *world;
    RCPackage *pkg = NULL;
    char *channel_str = NULL;
    char *pkg_name = NULL;
    RCChannel *channel;

    if (g_strcasecmp (node->name, "package"))
        goto finished;

    channel_str = xml_get_prop (node, "channel");
    if (channel_str == NULL) {
        /* FIXME: a better warning would be nice */
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Ignoring package tag without channel.");
        goto finished;
    }

    world = rc_get_world ();

    channel = channel_from_str (channel_str);
    if (channel == NULL) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Unknown channel '%s' in package tag.", channel_str);
        goto finished;
    }

    pkg_name = xml_get_content (node);

    pkg = rc_world_get_package (world, channel, pkg_name);

    if (pkg == NULL) {
        rc_debug (RC_DEBUG_LEVEL_WARNING,
                  "Can't find package '%s' in channel '%s'.",
                  pkg_name, channel_str);
    }

 finished:
    g_free (channel_str);
    g_free (pkg_name);

    return pkg;
}

/*
  rcd_autopull_from_xml_node processes XML that looks like this:

  <autopull when="1028480640" interval="86400">
    <channels>
      <channel>123</channel>
      <channel>456</channel>
    </channels>
    <packages>
      <package channel="789">frobnicator</package>
      <package channel="666">satan</package>
    </packages>
    <hold>
      <package channel="123">glibc</package>
      <package channel="456">pr0n-o-matic</package>
    </hold>
  </autopull>
*/

static RCDAutopull *
rcd_autopull_from_xml_node (xmlNode *node)
{
    RCDAutopull *pull = NULL;
    xmlNode *iter;
    char *when_str = NULL;
    char *interval_str = NULL;
    time_t when;
    guint32 interval;
    
    if (g_strcasecmp (node->name, "autopull"))
        return NULL;

    when_str = xml_get_prop (node, "when");
    interval_str = xml_get_prop (node, "interval");

    when = when_str ? atol (when_str) : 0;
    interval = interval_str ? atol (interval_str) : 0;

    g_free (when_str);
    g_free (interval_str);

    pull = rcd_autopull_new (when, interval);

    for (node = node->xmlChildrenNode; node; node = node->next) {

        if (! g_strcasecmp (node->name, "channels")) {

            for (iter = node->xmlChildrenNode; iter; iter = iter->next) {
                
                if (! g_strcasecmp (node->name, "channel")) {
                    char *channel_str = xml_get_content (node);
                    RCChannel *channel = channel_from_str (channel_str);

                    if (channel) {
                        pull->channels_to_update =
                            g_slist_prepend (pull->channels_to_update,
                                             rc_channel_ref (channel));
                    } else {
                        rc_debug (RC_DEBUG_LEVEL_WARNING,
                                  "Unknown channel '%s'.", channel_str);
                    }

                    g_free (channel_str);
                }
            }

        } else if (! g_strcasecmp (node->name, "packages")) {

            for (iter = node->xmlChildrenNode; iter; iter = iter->next) {

                if (! g_strcasecmp (node->name, "package")) {
                    RCPackage *package = package_from_xml_node (node);
                    /* package_from_xml_node prints a warning
                       if it returns NULL, so we don't have to do anything
                       in that case. */
                    if (package) {
                        pull->packages_to_update =
                            g_slist_prepend (pull->packages_to_update,
                                             rc_package_ref (package));
                    }
                }
            }

        } else if (! g_strcasecmp (node->name, "hold")) {

            for (iter = node->xmlChildrenNode; iter; iter = iter->next) {

                if (! g_strcasecmp (node->name, "package")) {
                    RCPackage *package = package_from_xml_node (node);
                    /* package_from_xml_node prints a warning
                       if it returns NULL, so we don't have to do anything
                       in that case. */
                    if (package) {
                        pull->packages_to_update =
                            g_slist_prepend (pull->packages_to_update,
                                             rc_package_ref (package));
                    }
                }
            }
        }

        node = node->next;
    }

    return pull;
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
