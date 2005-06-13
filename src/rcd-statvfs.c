#include <stdio.h>
#include <mntent.h>
#include <sys/statvfs.h>

int
main (int argc, char *argv[])
{
    FILE *f;
    struct mntent *ent;
    struct statvfs buf;
    
    f = setmntent ("/etc/mtab", "r");

    /* if we can't do our thing, assume things are not ok */
    if (f == NULL)
        return 1;

    while ((ent = getmntent (f)) != NULL) {
	if (statvfs (ent->mnt_dir, &buf) != 0)
	    return 1;
    }

    return 0;
}
