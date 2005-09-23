/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/* suse-product.c
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

#include "suse-product.h"
#include <rc-arch.h>
#include <rc-debug.h>
#include "wrapper.h"

typedef struct {
    gchar    *name;
    gchar    *version;
    RCArch    arch;
    gboolean  business;

    gchar    *patch_path;
    gchar    *rpm_path;
    gchar    *script_path;
} SuseProduct;

static GHashTable *products = NULL;

static const char *
tmp_you_path_prefix (void)
{
    static char *path = NULL;

    if (path)
        return path;

    path = g_build_filename (g_get_tmp_dir (), "lib");

    return path;
}

static const char *
tmp_you_path (void)
{
    static char *path = NULL;

    if (path)
        return path;

    path = g_build_filename (tmp_you_path_prefix (), "/YaST2/you/mnt");

    return path;
}

static void
destroy_product (SuseProduct *product)
{
    if (product == NULL)
        return;

    g_free (product->name);
    g_free (product->version);

    g_free (product->patch_path);
    g_free (product->rpm_path);
    g_free (product->script_path);

    g_free (product);
}

static gboolean
add_product (const gchar *name, const gchar *version, const gchar *arch,
             gboolean business, const gchar *patch_path, gpointer user_data)
{
    SuseProduct *p;
    gchar *suse_prefix;

    p = g_new0 (SuseProduct, 1);
    p->name = g_strdup (name);
    p->version = g_strdup (version);
    p->arch = rc_arch_from_string (arch);
    p->business = business;

    /* This sucks, but I don't know other ways to get only
       prefix out of yast */
    suse_prefix = g_path_get_dirname (patch_path);

    p->patch_path = g_build_filename (tmp_you_path (), patch_path, NULL);
    if (rc_mkdir (p->patch_path, 0755) < 0) {
        rc_debug (RC_DEBUG_LEVEL_ERROR,
                  "Can not use product '%s': Creation of directory '%s' failed",
                  name, p->patch_path);
        destroy_product (p);
        return TRUE;
    }

    p->rpm_path = g_build_filename (tmp_you_path (), suse_prefix, "rpm", NULL);
    if (rc_mkdir (p->rpm_path, 0755) < 0) {
        rc_debug (RC_DEBUG_LEVEL_ERROR,
                  "Can not use product '%s': Creation of directory '%s' failed",
                  name, p->rpm_path);
        destroy_product (p);
        return TRUE;
    }

    p->script_path = g_build_filename (tmp_you_path (), suse_prefix, "scripts", NULL);
    if (rc_mkdir (p->script_path, 0755) < 0) {
        rc_debug (RC_DEBUG_LEVEL_ERROR,
                  "Can not use product '%s': Creation of directory '%s' failed",
                  name, p->script_path);
        destroy_product (p);
        return TRUE;
    }

    g_free (suse_prefix);

    g_hash_table_insert (products, p->name, p);

    return TRUE;
}

void
suse_product_initialize (void)
{
    g_return_if_fail (products == NULL);

    products = g_hash_table_new_full (g_str_hash,
                                      g_str_equal,
                                      NULL,
                                      (GDestroyNotify) destroy_product);

    rc_you_wrapper_products_foreach (add_product, NULL);
}

void
suse_product_finalize (void)
{
    g_return_if_fail (products != NULL);

    g_hash_table_destroy (products);
    products = NULL;
    rc_rmdir (tmp_you_path_prefix ());
}

static SuseProduct *
suse_product_lookup (const gchar *product)
{
    SuseProduct *p;

    p = g_hash_table_lookup (products, product);
    if (p == NULL)
        rc_debug (RC_DEBUG_LEVEL_WARNING, "Can not find product '%s'",
                  product);

    return p;
}

const gchar *
suse_product_get_patchdir (const gchar *product)
{
    SuseProduct *p;

    g_return_val_if_fail (products != NULL, NULL);
    g_return_val_if_fail (product != NULL, NULL);

    p = suse_product_lookup (product);
    if (p)
        return p->patch_path;

    return NULL;
}

const gchar *
suse_product_get_rpmdir (const gchar *product)
{
    SuseProduct *p;

    g_return_val_if_fail (products != NULL, NULL);
    g_return_val_if_fail (product != NULL, NULL);

    p = suse_product_lookup (product);
    if (p)
        return p->rpm_path;

    return NULL;
}

const gchar *
suse_product_get_scriptdir (const gchar *product)
{
    SuseProduct *p;

    g_return_val_if_fail (products != NULL, NULL);
    g_return_val_if_fail (product != NULL, NULL);

    p = suse_product_lookup (product);
    if (p)
        return p->script_path;

    return NULL;
}
