/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * rcd-identity.c
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

#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <libredcarpet.h>

#include "rcd-identity.h"

#define PASSWORD_FILE SYSCONFDIR "/rcd.passwd"

RCDIdentity *
rcd_identity_new (void)
{
    RCDIdentity *id;

    id = g_new0 (RCDIdentity, 1);

    return id;
}

RCDIdentity *
rcd_identity_copy (RCDIdentity *id)
{
    RCDIdentity *copy;

    if (id == NULL)
        return NULL;

    copy = rcd_identity_new ();

    copy->username = g_strdup (id->username);
    copy->password = g_strdup (id->password);
    copy->privileges = id->privileges;

    return copy;
}

void
rcd_identity_free (RCDIdentity *id)
{
    if (id) {
        g_free (id->username);
        g_free (id->password);
        g_free (id);
    }
}

gboolean
rcd_identity_approve_action (RCDIdentity *id,
                             RCDPrivileges required_priv)
{
    g_return_val_if_fail (id != NULL, FALSE);

    return (id->privileges & required_priv) == required_priv;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

gboolean
rcd_identity_well_formed_username (const char *str)
{
    const char *c;

    if (! (str && *str))
        return FALSE;

    for (c = str; *c; ++c) {
        if (!(isalnum(*c) || *c == '_'))
            return FALSE;
    }

    return TRUE;
}

gboolean
rcd_identity_well_formed_password (const char *str)
{
    const char *c;
    
    if (! (str && *str))
        return FALSE;

    for (c = str; *c; ++c) {
        if (! isxdigit (*c))
            return FALSE;
    }

    return TRUE;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

gboolean
rcd_identity_password_file_is_secure (void)
{
    static gboolean first_insecure = TRUE;

    struct stat statbuf;
    gboolean bad_owner, bad_permissions;

    /* If it doesn't exist, that is fine. */
    if (stat (PASSWORD_FILE, &statbuf) != 0)
        return TRUE;

    /* Don't complain about the ownership of the file if we aren't
       running as root.  If we aren't, then we must have been run with
       --allow-non-root and so the user must not really care. */
    bad_owner = getuid () == 0 && statbuf.st_uid != 0;
    bad_permissions = statbuf.st_mode & 0077;

    if (bad_owner || bad_permissions) {
        if (first_insecure) { 
            int i;
            const char *message[] = {
                "***** WARNING ***** WARNING ***** WARNING ***** WARNING *****",
                "",
                "The rcd password file:",
                "",
                "     " PASSWORD_FILE,
                "",
                "is not secure.",
                "",
                "Password-based authentication will be disabled until this is fixed.",
                ""
                "To properly secure the file, execute the following as root:",
                "",
                NULL };

            for (i = 0; message[i]; ++i)
                rc_debug (RC_DEBUG_LEVEL_CRITICAL, message[i]);

            if (bad_owner)
                rc_debug (RC_DEBUG_LEVEL_CRITICAL, "  # chown root " PASSWORD_FILE);
            if (bad_permissions)
                rc_debug (RC_DEBUG_LEVEL_CRITICAL, "  # chmod 600 " PASSWORD_FILE);
            
            rc_debug (RC_DEBUG_LEVEL_CRITICAL, "");
            rc_debug (RC_DEBUG_LEVEL_CRITICAL, message[0]); /* more WARNING yelling */

            first_insecure = FALSE;
        }

        return FALSE;
    }

    /* We want to repeat the warning if we ever find the file to insecure
       after we have seen it to be secure. */
    first_insecure = TRUE;

    return TRUE;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static gboolean magic_foreach_password_terminate;

void
rcd_identity_foreach_from_password_file (RCDIdentityFn fn,
                                         gpointer      user_data)
{
    FILE *in;
    char buffer[1024];

    g_return_if_fail (fn != NULL);

    magic_foreach_password_terminate = FALSE;

    in = fopen (PASSWORD_FILE, "r");
    if (in == NULL)
        return;

    while (fgets (buffer, 1024, in)
           && !magic_foreach_password_terminate) {
        char *hash;

        /* Truncate the line at #, filtering out comments */
        hash = strchr (buffer, '#');
        if (hash)
            *hash = '\0';

        g_strstrip (buffer);

        if (buffer && *buffer) {
            char **user_info;

            user_info = g_strsplit (buffer, ":", 0);
            
            /* Just skip any malformed lines */
            if (user_info[0] && *user_info[0]
                && user_info[1] 
                && user_info[2]
                && !user_info[3]) {
                RCDIdentity id;
                id.username = user_info[0];
                id.password = user_info[1];
                id.privileges = rcd_privileges_from_string (user_info[2]);

                fn (&id, user_data);
            }

            g_strfreev (user_info);
        }
    }

    fclose (in);
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

struct IdentityFromFileInfo {
    const char *username;
    RCDIdentity *id;
};

static void
identity_from_file_cb (RCDIdentity *id,
                       gpointer user_data)
{
    struct IdentityFromFileInfo *info = user_data;

    if (! strcmp (info->username, id->username)) {

        info->id = rcd_identity_copy (id);

        /* Oh, this is just so evil. */
        magic_foreach_password_terminate = TRUE;
    }
}

RCDIdentity *
rcd_identity_from_password_file (const char *username)
{
    struct IdentityFromFileInfo info;

    g_return_val_if_fail (username != NULL, NULL);

    if (! *username)
        return NULL;

    info.username = username;
    info.id = NULL;

    rcd_identity_foreach_from_password_file (identity_from_file_cb,
                                             &info);
    
    return info.id;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

static FILE *
create_password_file (void)
{
    FILE *out;

    out = fopen (PASSWORD_FILE, "w");
    if (out) {
        chmod (PASSWORD_FILE, S_IRUSR | S_IWUSR);
    } else {
        rc_debug (RC_DEBUG_LEVEL_CRITICAL,
                  "Couldn't re-open password file '" PASSWORD_FILE "'");
    }

    return out;
}

/* ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** */

struct IdentityUpdateInfo {
    gboolean failed;
    FILE *out;
    RCDIdentity *new_id;
};

static void
write_identity (RCDIdentity *old_id,
                RCDIdentity *new_id,
                FILE        *out)
{
    gchar *priv_str;

    if (out == NULL)
        return;

    if (new_id == NULL)
        return;

    /* Merge old and new identities as necessary. */
    if (old_id) {

        if (new_id->password == NULL)
            new_id->password = g_strdup (old_id->password);

        if (new_id->privileges == -1)
            new_id->privileges = old_id->privileges;
    }

    priv_str = rcd_privileges_to_string (new_id->privileges);
 
    fprintf (out, "%s:%s:%s\n",
             new_id->username,
             new_id->password ? new_id->password : "",
             priv_str);

    g_free (priv_str);
}

static void
identity_update_cb (RCDIdentity *old_id,
                    gpointer     user_data)
{
    struct IdentityUpdateInfo *info = user_data;
    
    if (info->failed)
        return;

    if (info->out == NULL) {
        if (unlink (PASSWORD_FILE) != 0) {
            info->failed = TRUE;
        } else {
            info->out = create_password_file ();
            if (info->out == NULL)
                info->failed = TRUE;
        }
    }

    if (old_id == NULL || old_id->username == NULL)
        return;

    if (info->new_id && ! strcmp (old_id->username, info->new_id->username)) {
        write_identity (old_id, info->new_id, info->out);
        info->new_id = NULL;
    } else
        write_identity (NULL, old_id, info->out);
    
}

gboolean
rcd_identity_update_password_file (RCDIdentity *id)
{
    struct IdentityUpdateInfo info;

    info.failed = FALSE;
    info.out = NULL;
    info.new_id = id;

    rcd_identity_foreach_from_password_file (identity_update_cb,
                                             &info);

    if (info.out == NULL && ! info.failed) {

        /* If the password file doesn't exist or contains only
           comments, the identity_update_cb callback will never get
           called, so we have to create the password file manually in
           order for our final call to write_identity to have a place
           to put the information. */

        info.out = create_password_file ();
    }

    if (info.new_id != NULL && ! info.failed)
        write_identity (NULL, info.new_id, info.out);

    if (info.out && ! info.failed)
        fclose (info.out);

    return ! info.failed;
}

gboolean
rcd_identity_remove_from_password_file (const char *username)
{
    FILE *in, *out;
    char buffer[1024];
    int id_len;

    g_return_val_if_fail (username && *username, FALSE);

    in = fopen (PASSWORD_FILE, "r");

    if (unlink (PASSWORD_FILE) != 0) {
        fclose (in);
        return FALSE;
    }

    /* FIXME: If re-opening the password file fails, we will drop all
       of the user information.  Which is bad.  (Actually, this is a
       problem with several of these functions!) */
    out = create_password_file ();

    id_len = strlen (username);

    while (fgets (buffer, 1024, in)) {
        char *colon = strchr (buffer, ':');
        
        if (! (colon
               && colon - buffer == id_len
               && ! strncmp (buffer, username, colon - buffer)))
            fputs (buffer, out);
    }

    fclose (in);
    fclose (out);

    return TRUE;
}
