/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/* you-util.c
 * Copyright (C) 2004 Novell, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include "you-util.h"
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libredcarpet.h>
#include "rcd-rpc-util.h"
#include "rc-world-you.h"
#include "rc-you-package.h"
#include "suse-product.h"

/*****************************************************************************/
/* XML-RPC helpers */

struct InstalledFlags {
    RCYouPatch *patch;
    int installed;
    int name_installed;
};

static gboolean
installed_check_cb (RCYouPatch *sys_patch,
                    gpointer user_data)
{
    struct InstalledFlags *flags = user_data;
    int cmp;
    
    cmp = rc_packman_version_compare (rc_packman_get_global (),
                                      RC_PACKAGE_SPEC (flags->patch),
                                      RC_PACKAGE_SPEC (sys_patch));

    if (cmp == 0) {

        flags->installed = 1;

    } else {

        if (! flags->name_installed)
            flags->name_installed = cmp;
        else
            flags->name_installed = MAX (flags->name_installed, cmp);
    }

    return TRUE;
}

xmlrpc_value *
rc_you_patch_to_xmlrpc (RCYouPatch *patch, xmlrpc_env *env)
{
    xmlrpc_value *value = NULL;
    gboolean installed;
    gint name_installed;

    value = xmlrpc_struct_new (env);
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_SET_STRING (env, value, "product", patch->product);

    rcd_rc_package_spec_to_xmlrpc (RC_PACKAGE_SPEC (patch), value, env);
    XMLRPC_FAIL_IF_FAULT (env);

    if (patch->installed) {
        RCChannel *guess;

        installed = TRUE;
        name_installed = 1;

        guess = rc_world_multi_guess_patch_channel
            (RC_WORLD_MULTI (rc_get_world ()), patch);

        if (guess != NULL)
            RCD_XMLRPC_STRUCT_SET_STRING(env, value, "channel_guess",
                                         rc_channel_get_id (guess));
    } else {
        const char *name;
        struct InstalledFlags flags;
        flags.patch = patch;
        flags.installed = 0;
        flags.name_installed = 0;

        name = g_quark_to_string (RC_PACKAGE_SPEC (patch)->nameq);
        rc_world_multi_foreach_patch_by_name
            (RC_WORLD_MULTI (rc_get_world ()),
             name,
             RC_CHANNEL_SYSTEM,
             installed_check_cb,
             &flags);
        
        installed = flags.installed;
        name_installed = flags.name_installed;
    }
    RCD_XMLRPC_STRUCT_SET_INT(env, value, "installed", installed);
    XMLRPC_FAIL_IF_FAULT (env);
    RCD_XMLRPC_STRUCT_SET_INT(env, value, "name_installed", name_installed);
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_SET_STRING
        (env, value, "channel",
         !rc_channel_is_wildcard (patch->channel) && !rc_channel_is_hidden (patch->channel) ?
         rc_channel_get_id (patch->channel) : "");

    if (patch->importance != RC_IMPORTANCE_INVALID) {
        RCD_XMLRPC_STRUCT_SET_INT (env, value, "importance_num",
                                   (gint) patch->importance);
        RCD_XMLRPC_STRUCT_SET_STRING (env, value, "importance_str",
                                      rc_package_importance_to_string (patch->importance));
    }

    RCD_XMLRPC_STRUCT_SET_INT (env, value, "install_only", patch->install_only);

cleanup:
    if (env->fault_occurred) {
        if (value)
            xmlrpc_DECREF (value);
        value = NULL;
    }

    return value;
}

xmlrpc_value *
rc_you_patch_slist_to_xmlrpc_array (RCYouPatchSList *list, xmlrpc_env *env)
{
    GSList *iter;
    xmlrpc_value *array = NULL;

    array = xmlrpc_build_value (env, "()");
    XMLRPC_FAIL_IF_FAULT (env);

    for (iter = list; iter; iter = iter->next) {
        RCYouPatch *patch = iter->data;
        xmlrpc_value *value;

        value = rc_you_patch_to_xmlrpc (patch, env);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_array_append_item (env, array, value);
        XMLRPC_FAIL_IF_FAULT (env);

        xmlrpc_DECREF (value);
    }

cleanup:
    if (env->fault_occurred) {
        if (array)
            xmlrpc_DECREF (array);
        array = NULL;
    }

    return array;
}

RCYouPatch *
rc_you_patch_from_xmlrpc_patch (xmlrpc_value *value,
                                xmlrpc_env   *env)
{
    char *channel_id, *name;
    RCWorldMulti *world;
    RCYouPatch *patch = NULL;

    RCD_XMLRPC_STRUCT_GET_STRING (env, value, "name", name);
    XMLRPC_FAIL_IF_FAULT (env);

    RCD_XMLRPC_STRUCT_GET_STRING (env, value, "channel", channel_id);
    XMLRPC_FAIL_IF_FAULT (env);

    world = RC_WORLD_MULTI (rc_get_world ());

    if (channel_id) {
        RCChannel *channel;

        channel = rc_world_get_channel_by_id (RC_WORLD (world), channel_id);
        if (!channel) {
            xmlrpc_env_set_fault (env, RCD_RPC_FAULT_INVALID_CHANNEL,
                                  "Unable to find channel");
            goto cleanup;
        }

        patch = rc_world_multi_get_patch (world, channel, name);
        if (!patch) {
            xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PACKAGE_NOT_FOUND,
                                  "Unable to find patch");
            goto cleanup;
        }
    } else {
        patch = rc_world_multi_get_patch (world, RC_CHANNEL_SYSTEM, name);
        if (!patch) {
            xmlrpc_env_set_fault (env, RCD_RPC_FAULT_PACKAGE_NOT_FOUND,
                                  "Unable to find patch");
            goto cleanup;
        }
    }

    rc_you_patch_ref (patch);

cleanup:
    return patch;
}

RCYouPatch *
rc_xmlrpc_to_rc_you_patch (xmlrpc_value *value,
                           xmlrpc_env   *env,
                           int           flags)
{
    RCYouPatch *patch = NULL;

    if (flags & RC_YOU_PATCH_FROM_XMLRPC_PATCH &&
        xmlrpc_value_type (value) == XMLRPC_TYPE_STRUCT)
        patch = rc_you_patch_from_xmlrpc_patch (value, env);
    else
        xmlrpc_env_set_fault (env, RCD_RPC_FAULT_INVALID_STREAM_TYPE,
                              "Invalid patch stream type");

    return patch;
}

RCYouPatchSList *
rc_xmlrpc_array_to_rc_you_patch_slist (xmlrpc_value *value,
                                       xmlrpc_env   *env,
                                       int           flags)
{
    RCYouPatchSList *patch_list = NULL;
    int size = 0;
    int i;

    size = xmlrpc_array_size (env, value);
    XMLRPC_FAIL_IF_FAULT (env);

    for (i = 0; i < size; i++) {
        xmlrpc_value *v;
        RCYouPatch *patch;

        v = xmlrpc_array_get_item (env, value, i);
        XMLRPC_FAIL_IF_FAULT (env);

        patch = rc_xmlrpc_to_rc_you_patch (v, env, flags);
        XMLRPC_FAIL_IF_FAULT (env);

        patch_list = g_slist_prepend (patch_list, patch);
    }

cleanup:
    if (env->fault_occurred) {
        rc_you_patch_slist_unref (patch_list);
        g_slist_free (patch_list);

        return NULL;
    }

    return patch_list;
}

/*****************************************************************************/
/* YaST directory structure */

static const gchar *
get_you_pkgdir (const gchar *product,
                const gchar *tmp_name,
                const gchar *filename)
{
    const gchar *rpm_dir;
    RCPackage *pkg;
    static gchar *dir = NULL;

    if (dir)
        g_free (dir);

    if (!rc_file_exists (tmp_name))
        return NULL;

    if ((rpm_dir = suse_product_get_rpmdir (product)) == NULL)
        return NULL;

    pkg = rc_packman_query_file (rc_packman_get_global (), tmp_name);
    if (!pkg) {
        rc_debug (RC_DEBUG_LEVEL_ERROR,
                  "Downloaded package does not appear to be a valid package");
        return NULL;
    }

    dir = g_build_filename (rpm_dir, rc_arch_to_string (pkg->arch), NULL);
    rc_package_unref (pkg);

    if (rc_mkdir (dir, 0755) < 0) {
        g_free (dir);
        dir = NULL;
    }

    return dir;
}

static void
write_directory_files (RCYouPatchSList *patches, GError **error)
{
    RCYouPatchSList *iter;
    const gchar *dir;
    gchar *dir_file, *buf;
    int fd;
    gboolean success;

    for (iter = patches; iter; iter = iter->next) {
        RCYouPatch *patch = iter->data;

        dir = suse_product_get_patchdir (patch->product);
        if (!dir) {
            g_set_error (error, RC_ERROR, RC_ERROR,
                         "Can not get patch directory for product '%s'",
                         patch->product);
            return;
        }

        dir_file = g_build_filename (dir, "directory.3", NULL);
        fd = open (dir_file, O_WRONLY | O_CREAT | O_APPEND);
        g_free (dir_file);
        if (fd < 0) {
            g_set_error (error, RC_ERROR, RC_ERROR,
                         "Can not open directory file: %s", strerror (errno));
            return;
        }

        buf = g_strdup_printf ("%s\n", patch->file->filename);
        success = rc_write (fd, (void *) buf, strlen (buf));
        g_free (buf);
        rc_close (fd);

        if (!success) {
            g_set_error (error, RC_ERROR, RC_ERROR,
                         "Can not write to directory file: %s", strerror (errno));
            return;
        }
    }
}

static void
write_you_file (RCYouFile *file, const gchar *dest_dir)
{
    gchar *dest_file;

    g_return_if_fail (dest_dir != NULL);

    if (file == NULL)
        return;

    if (file->local_path == NULL) {
        rc_debug (RC_DEBUG_LEVEL_ERROR,
                  "Can not write patch file %s: download failed",
                  file->filename);
        return;
    }

    dest_file = g_build_filename (dest_dir, file->filename, NULL);
    rc_cp (file->local_path, dest_file);
    g_free (dest_file);
}

static void
write_patches (RCYouPatchSList *patches)
{
    GSList *iter, *pkg_iter;

    for (iter = patches; iter; iter = iter->next) {
        RCYouPatch *patch = iter->data;

        write_you_file (patch->file,
                        suse_product_get_patchdir (patch->product));
        write_you_file (patch->pre_script,
                        suse_product_get_scriptdir (patch->product));
        write_you_file (patch->post_script,
                        suse_product_get_scriptdir (patch->product));

        for (pkg_iter = patch->packages; pkg_iter; pkg_iter = pkg_iter->next) {
            RCYouPackage *pkg = pkg_iter->data;

            /* Touch patch rpm only if "real" rpm is not provided */

            if (pkg->base_package)
                write_you_file (pkg->base_package,
                                get_you_pkgdir (patch->product,
                                                pkg->base_package->local_path,
                                                pkg->base_package->filename));
            else if (pkg->patch_rpm)
                write_you_file (pkg->patch_rpm,
                                get_you_pkgdir (patch->product,
                                                pkg->patch_rpm->local_path,
                                                pkg->patch_rpm->filename));
        }
    }
}

void
create_you_directory_structure (RCYouPatchSList *patches, GError **error)
{
    suse_product_initialize ();

    write_directory_files (patches, error);
    if (*error)
        return;

    write_patches (patches);
}

void
clean_you_directory_structure (void)
{
    suse_product_finalize ();
}

/*****************************************************************************/
/* XML parser */

typedef enum {
    PARSER_TOPLEVEL = 0,
    PARSER_PATCH,
    PARSER_INFORMATION,
    PARSER_PACKAGES,
    PARSER_PACKAGE,
} RCYouPatchSAXContextState;

struct _RCYouPatchSAXContext {
    RCChannel       *channel;
    gboolean         processing;
    xmlParserCtxt   *xml_context;
    RCYouPatchSAXContextState state;

    RCYouPatchSList *all_patches;

    /* Temporary state */
    RCYouPatch        *current_patch;
    RCYouPackage      *current_package;

    char            *text_buffer;
};

/* Like g_strstrip(), only returns NULL on an empty string */
static char *
rc_xml_strip (char *str)
{
    char *s;

    if (str == NULL)
        return NULL;

    s = g_strstrip (str);

    if (s && *s)
        return s;
    else
        return NULL;
}

static void
sax_start_document(void *data)
{
    RCYouPatchSAXContext *ctx = (RCYouPatchSAXContext *) data;

    g_return_if_fail(!ctx->processing);

    if (getenv ("RC_SPEW_XML"))
        rc_debug (RC_DEBUG_LEVEL_ALWAYS, "* Start document");

    ctx->processing = TRUE;
} /* sax_start_document */

static void
sax_end_document(void *data)
{
    RCYouPatchSAXContext *ctx = (RCYouPatchSAXContext *) data;

    g_return_if_fail(ctx->processing);

    if (getenv ("RC_SPEW_XML"))
        rc_debug (RC_DEBUG_LEVEL_ALWAYS, "* End document");

    ctx->processing = FALSE;

    g_free (ctx->text_buffer);
    ctx->text_buffer = NULL;

} /* sax_end_document */

static void
parser_toplevel_start (RCYouPatchSAXContext *ctx,
                       const xmlChar *name,
                       const xmlChar **attrs)
{
    if (!strcmp(name, "patch")) {
        g_assert(ctx->current_patch == NULL);

        ctx->state = PARSER_PATCH;

        ctx->current_patch = rc_you_patch_new ();

        ctx->current_patch->channel = ctx->channel;
        rc_channel_ref (ctx->channel);
    } else {
        if (getenv ("RC_SPEW_XML"))
            rc_debug (RC_DEBUG_LEVEL_ALWAYS, "! Not handling %s", name);
    }
} /* parser_toplevel_start */

static void
parser_patch_start (RCYouPatchSAXContext *ctx,
                    const xmlChar *name,
                    const xmlChar **attrs)
{
    g_assert(ctx->current_patch != NULL);

    /* Only care about the containers here */
    if (!strcmp(name, "packages")) {
        ctx->state = PARSER_PACKAGES;
    } else if (!strcmp(name, "preinformation")) {
        /* Only care for english */
        if (attrs != NULL && attrs[0] != NULL && attrs[1] != NULL &&
            !strcmp(attrs[0], "language") &&
            !strcmp(attrs[1], "english"))
            ctx->state = PARSER_INFORMATION;
    }
    else {
        if (getenv ("RC_SPEW_XML"))
            rc_debug (RC_DEBUG_LEVEL_ALWAYS, "! Not handling %s", name);
    }

} /* parser_patch_start */

static void
parser_packages_start(RCYouPatchSAXContext *ctx,
                      const xmlChar *name,
                      const xmlChar **attrs)
{
    g_assert(ctx->current_patch != NULL);

    if (!strcmp(name, "package")) {
        g_assert (ctx->current_package == NULL);

        ctx->current_package = rc_you_package_new ();
        ctx->state = PARSER_PACKAGE;
    }
    else {
        if (getenv ("RC_SPEW_XML"))
            rc_debug (RC_DEBUG_LEVEL_ALWAYS, "! Not handling %s", name);
    }
}

static void
sax_start_element(void *data, const xmlChar *name, const xmlChar **attrs)
{
    RCYouPatchSAXContext *ctx = (RCYouPatchSAXContext *) data;
    int i;

    if (ctx->text_buffer) {
        g_free (ctx->text_buffer);
        ctx->text_buffer = NULL;
    }

    if (getenv ("RC_SPEW_XML"))
        rc_debug (RC_DEBUG_LEVEL_ALWAYS, "* Start element (%s)", name);

    if (attrs) {
        for (i = 0; attrs[i]; i += 2) {
            if (getenv ("RC_SPEW_XML"))
                rc_debug (RC_DEBUG_LEVEL_ALWAYS, "   - Attribute (%s=%s)", attrs[i], attrs[i+1]);
        }
    }

    if (!strcmp(name, "channel") || !strcmp(name, "subchannel")) {
        /* Unneeded container tags.  Ignore */
        return;
    }

    switch (ctx->state) {
    case PARSER_TOPLEVEL:
        parser_toplevel_start(ctx, name, attrs);
        break;
    case PARSER_PATCH:
        parser_patch_start(ctx, name, attrs);
        break;
    case PARSER_INFORMATION:
        /* NOP */
        break;
    case PARSER_PACKAGES:
        parser_packages_start(ctx, name, attrs);
        break;
    default:
        break;
    }
}

static RCPackageImportance
rc_you_kind_string_to_importance (const gchar *kind)
{
    RCPackageImportance imp;

    if      (!strcmp (kind, "security"))    imp = RC_IMPORTANCE_URGENT;
    else if (!strcmp (kind, "recommended")) imp = RC_IMPORTANCE_SUGGESTED;
    else if (!strcmp (kind, "optional"))    imp = RC_IMPORTANCE_FEATURE;
    else if (!strcmp (kind, "patchlevel"))  imp = RC_IMPORTANCE_FEATURE;
    else if (!strcmp (kind, "document"))    imp = RC_IMPORTANCE_MINOR;
    else {
        rc_debug (RC_DEBUG_LEVEL_MESSAGE, "Invalid patch kind '%s'", kind);
        imp = RC_IMPORTANCE_INVALID;
    }

    return imp;
}

static void
parser_patch_end (RCYouPatchSAXContext *ctx, const xmlChar *name)
{
    g_assert(ctx->current_patch != NULL);

    if (!strcmp(name, "patch")) {
        ctx->all_patches = g_slist_prepend (ctx->all_patches,
                                            ctx->current_patch);
        ctx->current_patch = NULL;
        ctx->state = PARSER_TOPLEVEL;
    }

    else if (!strcmp(name, "product")) {
        ctx->current_patch->product = rc_xml_strip (ctx->text_buffer);
        ctx->text_buffer = NULL;
    } else if (!strcmp(name, "patchname")) {
        ctx->current_patch->spec.nameq =
            g_quark_from_string (rc_xml_strip (ctx->text_buffer));
    } else if (!strcmp(name, "filename")) {
        ctx->current_patch->file =
            rc_you_file_new (rc_xml_strip (ctx->text_buffer));
    } else if (!strcmp(name, "patchversion")) {
        ctx->current_patch->spec.version = rc_xml_strip (ctx->text_buffer);
        ctx->text_buffer = NULL;

        /* Release should be set, but patches don't have releases */
        ctx->current_patch->spec.release = g_strdup ("");
    } else if (!strcmp(name, "buildtime")) {
        ctx->current_patch->buildtime =
            rc_string_to_guint32_with_default(ctx->text_buffer, 0);
    } else if (!strcmp(name, "updateonlyinstalled")) {
        ctx->current_patch->install_only = TRUE;
    } else if (!strcmp(name, "kind")) {
        ctx->current_patch->importance =
            rc_you_kind_string_to_importance (rc_xml_strip (ctx->text_buffer));
    } else if (!strcmp(name, "prescript")) {
        ctx->current_patch->pre_script =
            rc_you_file_new (rc_xml_strip (ctx->text_buffer));
    } else if (!strcmp(name, "postscript")) {
        ctx->current_patch->pre_script =
            rc_you_file_new (rc_xml_strip (ctx->text_buffer));
    }

    else if (!strcmp(name, "shortdescription")) {
        ctx->current_patch->summary = rc_xml_strip (ctx->text_buffer);
        ctx->text_buffer = NULL;
    } else if (!strcmp(name, "longdescription")) {
        ctx->current_patch->description = ctx->text_buffer;
        ctx->text_buffer = NULL;
    } else if (!strcmp(name, "arch")) {
        ctx->current_patch->arch =
            rc_arch_from_string (rc_xml_strip (ctx->text_buffer));
    }

} /* parser_patch_end */

static void
parser_information_end (RCYouPatchSAXContext *ctx, const xmlChar *name)
{
    g_assert(ctx->current_patch != NULL);

    if (!strcmp(name, "preinformation")) {
        ctx->current_patch->license = rc_xml_strip (ctx->text_buffer);
        ctx->text_buffer = NULL;
        ctx->state = PARSER_PATCH;
    }
} /* parser_information_end */

static void
parser_packages_end (RCYouPatchSAXContext *ctx, const xmlChar *name)
{
    g_assert(ctx->current_patch != NULL);

    if (!strcmp(name, "packages")) {
        g_assert(ctx->current_package == NULL);

        ctx->state = PARSER_PATCH;
    }
} /* parser_packages_end */

static void
parser_package_end (RCYouPatchSAXContext *ctx, const xmlChar *name)
{
    g_assert (ctx->current_patch != NULL);
    g_assert (ctx->current_package != NULL);

    if (!strcmp (name, "package")) {
        ctx->current_patch->packages = g_slist_prepend
            (ctx->current_patch->packages,
             rc_you_package_ref (ctx->current_package));
        ctx->current_package = NULL;
        ctx->state = PARSER_PACKAGES;
    }

    /*
        <filename>sysconfig-0.31.0-15.8.i586.rpm</filename>
        <patchrpmfilename>sysconfig-0.31.0-15.8.i586.patch.rpm</patchrpmfilename>
        <patchrpmbasedon>0.31.0-15 0.31.0-15.3</patchrpmbasedon>
        <patchrpminstallsize>424070</patchrpminstallsize>
        <patchrpmdlsize>117300</patchrpmdlsize>
    */

    else if (!strcmp (name, "filename")) {
        ctx->current_package->base_package =
            rc_you_file_new (rc_xml_strip (ctx->text_buffer));
    } else if (!strcmp (name, "patchrpmfilename")) {
        ctx->current_package->patch_rpm =
            rc_you_file_new (rc_xml_strip (ctx->text_buffer));
    } else if (!strcmp (name, "patchrpminstallsize")) {
        ctx->current_package->patch_rpm_size =
            rc_string_to_guint32_with_default(ctx->text_buffer, 0);
    } else if (!strcmp (name, "patchrpmdlsize")) {
        ctx->current_package->patch_rpm_dlsize =
            rc_string_to_guint32_with_default(ctx->text_buffer, 0);
    }
    /* FIXME: Eventually we should parse it, but since we can never
       get enough information about patch packages, there's no point
       in parsing this

       else if (!strcmp (name, "patchrpmbasedon")) {
        
    }
    */
}

static void
sax_end_element(void *data, const xmlChar *name)
{
    RCYouPatchSAXContext *ctx = (RCYouPatchSAXContext *) data;
    
    if (!strcmp (name, "channel") || !strcmp (name, "subchannel")) {
        /* Unneeded container tags.  Ignore */
        goto DONE;
    }

    switch (ctx->state) {
    case PARSER_PATCH:
        parser_patch_end(ctx, name);
        break;
    case PARSER_INFORMATION:
        parser_information_end(ctx, name);
    case PARSER_PACKAGES:
        parser_packages_end(ctx, name);
        break;
    case PARSER_PACKAGE:
        parser_package_end(ctx, name);
    default:
        break;
    }

 DONE:
    g_free (ctx->text_buffer);
    ctx->text_buffer = NULL;
}

static void
sax_characters(void *data, const xmlChar *ch, int len)
{
    RCYouPatchSAXContext *ctx = (RCYouPatchSAXContext *) data;

    if (ctx->text_buffer) {
        int current_len = strlen (ctx->text_buffer);
        char *buf = g_malloc0 (current_len + len + 1);
        strcpy (buf, ctx->text_buffer);
        strncpy (buf + current_len, ch, len);
        g_free (ctx->text_buffer);
        ctx->text_buffer = buf;
    } else {
        ctx->text_buffer = g_strndup(ch, len);
    }
}

static void
sax_warning(void *data, const char *msg, ...)
{
    va_list args;
    char *tmp;

    va_start(args, msg);

    tmp = g_strdup_vprintf(msg, args);
    rc_debug (RC_DEBUG_LEVEL_WARNING, "* SAX Warning: %s", tmp);
    g_free(tmp);

    va_end(args);
}

static void
sax_error(void *data, const char *msg, ...)
{
    va_list args;
    char *tmp;

    va_start(args, msg);

    tmp = g_strdup_vprintf(msg, args);
    rc_debug (RC_DEBUG_LEVEL_ERROR, "* SAX Error: %s", tmp);
    g_free(tmp);

    va_end(args);
}

static xmlSAXHandler sax_handler = {
    NULL,      /* internalSubset */
    NULL,      /* isStandalone */
    NULL,      /* hasInternalSubset */
    NULL,      /* hasExternalSubset */
    NULL,      /* resolveEntity */
    NULL,      /* getEntity */
    NULL,      /* entityDecl */
    NULL,      /* notationDecl */
    NULL,      /* attributeDecl */
    NULL,      /* elementDecl */
    NULL,      /* unparsedEntityDecl */
    NULL,      /* setDocumentLocator */
    sax_start_document,      /* startDocument */
    sax_end_document,        /* endDocument */
    sax_start_element,       /* startElement */
    sax_end_element,         /* endElement */
    NULL,      /* reference */
    sax_characters,          /* characters */
    NULL,      /* ignorableWhitespace */
    NULL,      /* processingInstruction */
    NULL,      /* comment */
    sax_warning,      /* warning */
    sax_error,      /* error */
    sax_error,      /* fatalError */
};

void
rc_you_patch_sax_context_parse_chunk (RCYouPatchSAXContext *ctx,
                                      const char *xmlbuf,
                                      int size)
{
    xmlSubstituteEntitiesDefault (TRUE);

    if (!ctx->xml_context)
        ctx->xml_context = xmlCreatePushParserCtxt (&sax_handler, ctx,
                                                    NULL, 0, NULL);

    xmlParseChunk (ctx->xml_context, xmlbuf, size, 0);
}

RCYouPatchSList *
rc_you_patch_sax_context_done (RCYouPatchSAXContext *ctx)
{
    RCYouPatchSList *all_patches = NULL;

    if (ctx->processing)
        xmlParseChunk (ctx->xml_context, NULL, 0, 1);

    if (ctx->xml_context)
        xmlFreeParserCtxt (ctx->xml_context);

    if (ctx->current_patch) {
        g_warning ("Incomplete patch lost");
        rc_you_patch_unref (ctx->current_patch);
    }

    g_free (ctx->text_buffer);
    all_patches = ctx->all_patches;
    g_free (ctx);

    return all_patches;
}

RCYouPatchSAXContext *
rc_you_patch_sax_context_new (RCChannel *channel)
{
    RCYouPatchSAXContext *ctx;

    ctx = g_new0 (RCYouPatchSAXContext, 1);
    ctx->channel = channel;

    return ctx;
}

gint
rc_extract_patches_from_helix_buffer (const guint8 *data, int len,
                                      RCChannel *channel,
                                      RCPatchFn callback,
                                      gpointer user_data)
{
    GByteArray *decompressed_data = NULL;
    RCYouPatchSAXContext *ctx;
    RCYouPatchSList *patches, *iter;
    gint count = 0;

    if (data == NULL || len == 0)
        return 0;

    if (rc_memory_looks_compressed (data, len)) {
        if (rc_uncompress_memory (data, len, &decompressed_data) < 0)
            return 0;

        data = decompressed_data->data;
        len = decompressed_data->len;
    }

    ctx = rc_you_patch_sax_context_new (channel);
    rc_you_patch_sax_context_parse_chunk (ctx, data, len);
    patches = rc_you_patch_sax_context_done (ctx);

    if (decompressed_data)
        g_byte_array_free (decompressed_data, TRUE);

    count = g_slist_length (patches);

    if (callback) {
        for (iter = patches; iter; iter = iter->next)
            callback ((RCYouPatch *) iter->data, user_data);
    }

    rc_you_patch_slist_unref (patches);
    g_slist_free (patches);

    return count;
}
