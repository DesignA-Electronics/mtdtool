/* ======================================================================
 *
 * File    : mtdlib.c
 * Project : Snapper
 * Author  : Andre Renaud/Simon Glass
 * Company : Bluewater Systems Ltd
 *           http://www.bluewatersys.com
 *
 * Provides an access library for MTD devices
 *
 * Licensed under GPLv2
 *
 * ======================================================================
 */

#define _LARGEFILE64_SOURCE
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#ifndef __USE_UNIX98
#define __USE_UNIX98
#endif

#include <unistd.h>

#include "mtd/mtd-user.h"
#include "mtdlib.h"

/* all mtd functions returns an integer error code or byte count

   < 0  means error
   >= 0 means ok

On error, you can call mtd_get_error() to find out what happened.

Once an error has occured, further operations will be ignored until
you call mtd_clear_error() */

#define mtd_malloc malloc
#define mtd_free free
#define min(x, y)                                                            \
    ({                                                                       \
        typeof(x) _x = (x);                                                  \
        typeof(y) _y = (y);                                                  \
        _x < _y ? _x : _y;                                                   \
    })
#define max(x, y)                                                            \
    ({                                                                       \
        typeof(x) _x = (x);                                                  \
        typeof(y) _y = (y);                                                  \
        _x > _y ? _x : _y;                                                   \
    })

enum {
    NAND_SMALL_BADBLOCK_POS = 5,
    NAND_LARGE_BADBLOCK_POS = 0,
};

/* information about the various cards available. A card is a thing which
can have multiple partitions. When it is inserted, it makes those
partitions available as /dev/mtd<x> devices */

// information that we keep about each open mtd device

struct mtd_info {
    int fd;                    // file descriptor for mtd
    int err;                   // non-zero if we've had an error
    struct mtd_info_user info; // mtd layer's info
    int page_size;             // size of a page in bytes, excluding OOB data
    int block_size;            // size of a block in bytes, excluding OOB data
    int pages_per_block;       // numbers of pages in a block
    int64_t size;              // total device size
    uint64_t block_mask;       // mask to move a position to start of block
    uint64_t page_mask;        // mask to move a position to start of page
    unsigned block_shift;      // amount to << block number to get address
    unsigned page_shift;       // amount to << page number to get address
    unsigned block_count;      // number of blocks
    unsigned page_count;       // number of pages
    struct nand_oobinfo old_oob; // saved oob info
    char errmess[200];           // last error message
    char fname[50];              // filename of mtd char device
    int ioctl_64;                // Does the kernel support 64 bit ioctls?

    int locking; // Locking support
};

// do an operation if there is no existing error
// returns error code on error
#define DO_OP(op, x) checkerr(mtd, op, x)

/* check if we have an error based on the supplied return value. If there is
an error, it is recorded and this function returns 1. Otherwise it returns
0.

If an error occurs, the error message will be recorded of the form:

      <op>: <strerror>

   \param mtd      the mtd to check
   \param op       a string representing the operation being performed
   \param err      error return value from operation

   \returns 0 if ok, -1 on error */

static int checkerr(mtd_info *mtd, char *op, int err)
{
    if (err < 0) {
        // this will lock out further operations
        return mtd_set_error(mtd, op, -errno, "%s", strerror(errno));
    } else
        mtd->err = err;
    return 0;
}

static off_t mtd_file_size(const char *filename)
{
    struct stat buf;

    if (stat(filename, &buf) != 0) {
        int e = errno;
        fprintf(stderr, "Unable to stat %s: %s\n", filename, strerror(e));
        return -e;
    }

    return buf.st_size;
}

/** prints the current mtd error if any. Returns -1 if there is an error,
else 0. This can be called even if there is no error, and it will do
nothing */

int mtd_perr(mtd_info *mtd)
{
    if (mtd->err < 0) {
        printf("mtd %s: %s\n", mtd->fname, mtd->errmess);
        return -1;
    }
    return 0;
}

/** returns the error code of the last error, and a pointer to the message */

int mtd_get_error(mtd_info *mtd, char **message)
{
    *message = mtd->errmess;
    return mtd->err;
}

/** returns the error message (always returns non-NULL) */

char *mtd_strerror(mtd_info *mtd)
{
    return mtd->errmess;
}

/** sets an error in the mtd (error code will be -1). This function always
   returns -1

   \param mtd      the mtd which has an error
   \param op       a string representing the operation being performed */

int mtd_set_error(mtd_info *mtd, char *op, int err, char *fmt, ...)
{
    va_list ptr;
    char *s = mtd->errmess;

    va_start(ptr, fmt);
    s += sprintf(s, "%s: %d - ", op, err);
    vsprintf(s, fmt, ptr);
    va_end(ptr);

    /* Don't print the ENOTTY messages if we haven't yet determined
     * 64-bit ioctl status
     */
    if (mtd->ioctl_64 != -1 || err == ENOTTY)
        fprintf(stderr, "MTDERROR: %s\n", mtd->errmess);

    mtd->err = err;
    return mtd->err;
}

/** find the first bit set in a number (bit 0 to 63). Returns -1 if nothing
is set */

static int ffs_bit(uint64_t pos)
{
    int i;

    for (i = 0; i < 64; i++)
        if (pos & ((unsigned long long)1 << i))
            return i;
    return -1;
}

static int64_t sysfs_read_integer(const char *path, ...)
{
    char filename[256];
    va_list ap;
    FILE *fp;
    char buffer[1024];
    int ret;

    va_start(ap, path);
    vsnprintf(filename, sizeof(filename) - 1, path, ap);
    va_end(ap);
    filename[sizeof(filename) - 1] = '\0';

    if ((fp = fopen(filename, "rb")) == NULL)
        return -1;
    ret = fread(buffer, 1, sizeof(buffer) - 1, fp);
    if (ret < 0) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    buffer[ret] = '\0';
    return strtoll(buffer, NULL, 0);
}

/** open an mtd, optionally for readonly

   \returns 0 if all ok, -ve on error, -EBUSY if already open */

int mtd_open(mtd_info *mtd, int readonly)
{
    int flags = O_SYNC;
    int fd;
    struct stat st;
    int64_t size;

    if (mtd->fd != -1) {
        fprintf(stderr, "Already open\n");
        return mtd_set_error(mtd, "mtd_open", -EBUSY, "already open");
    }
    flags |= readonly ? O_RDONLY : O_RDWR;
    fd = open(mtd->fname, flags);
    DO_OP("mtd_open", fd);
    if (fd < 0) {
        fprintf(stderr, "Unable to open '%s' - %s", mtd->fname,
                strerror(errno));
        return -1;
    }
    if ((fstat(fd, &st) < 0) || !S_ISCHR(st.st_mode)) {
        close(fd);
        return mtd_set_error(mtd, "mtd_open", -EINVAL, "Not a device file");
    }
    mtd->fd = fd;
    DO_OP("mtd_open info", ioctl(mtd->fd, MEMGETINFO, &mtd->info));

    mtd->block_size = mtd->info.erasesize;
    mtd->page_size =
        mtd->info.writesize ? mtd->info.writesize : mtd->block_size;
    if (!mtd->page_size) {
        fprintf(stderr,
                "Can't determine page size: writesize = %d, erasesize = %d\n"
                "(is this really a /dev/mtd file?\n",
                mtd->info.writesize, mtd->info.erasesize);
        close(mtd->fd);
        mtd->fd = -1;
        return -1;
    }
    /* Allow this to fail, and then fall back to the old mechanism */
    size = sysfs_read_integer("/sys/class/mtd/mtd%d/size",
                              minor(st.st_rdev) / 2);
    if (size < 0) {
        mtd->size = mtd->info.size;
    } else {
        mtd->size = size;
    }
    mtd->ioctl_64 = -1; // unknown
    mtd->pages_per_block = mtd->block_size / mtd->page_size;
    mtd->block_mask = ~(mtd->block_size - 1);
    mtd->page_mask = ~(mtd->page_size - 1);
    mtd->block_shift = ffs_bit(mtd->block_size);
    mtd->page_shift = ffs_bit(mtd->page_size);
    mtd->block_count = mtd->size / mtd->block_size;
    mtd->page_count = mtd->block_count * mtd->pages_per_block;
    /* Assume that the device supports locking */
    mtd->locking = 1;

    /*
       printf ("block size = %d, block_shift = %d, mask = %" PRIx64 "\n",
          mtd->block_size, mtd->block_shift, mtd->block_mask);
       printf ("page size = %d, page_shift = %d, mask = %" PRIx64 "\n",
          mtd->page_size, mtd->page_shift, mtd->page_mask);
    */
    return 0;
}

/** create a new (unconnected) mtd */

static mtd_info *mtd_new(void)
{
    mtd_info *mtd;

    mtd = (mtd_info *)mtd_malloc(sizeof *mtd);
    if (mtd) {
        memset(mtd, '\0', sizeof *mtd);
        mtd->fd = -1;
    } else
        fprintf(stderr, "Unable to malloc\n");
    return mtd;
}

/** create a new mtd from the given filename, which must be of the form
/dev/mtd<x>, where <x> is an integer from 0...max_mtd_device */

mtd_info *mtd_new_filename(const char *fname, int readonly)
{
    mtd_info *mtd;
    int err;

    mtd = mtd_new();
    if (!mtd)
        return NULL;
    strcpy(mtd->fname, fname);
    err = mtd_open(mtd, readonly);
    if (err < 0) {
        fprintf(stderr, "MTD Error: %d: %s\n", mtd->err, mtd->errmess);
        mtd_dispose(mtd);
        return NULL;
    }
    return mtd;
}

/* given a partition name, like "Internal0 Root Filesystem", this returns
the device number associated with it. For example, with /proc/mtd output
of:

mtd0: 00200000 00004000 "Internal0 Linux Kernel"
mtd1: 00400000 00004000 "Internal0 Root Filesystem"
mtd2: 00a00000 00004000 "Internal0 Data Filesystem"
mtd3: 01000000 00004000 "Internal0 Whole Card"

this function would for the example return 1 */

int mtd_find_part_name(const char *part_name)
{
    char buffer[200];
    char *name;
    int id = -1;
    int len = strlen(part_name);
    int i;
    FILE *f;

    // scan /proc/mtd looking for the name
    f = fopen("/proc/mtd", "r");
    if (f)
        while (!feof(f)) {
            if (fgets(buffer, sizeof(buffer), f) == NULL)
                break;

            name = buffer;

            for (i = 0; i < 3; i++) {
                name = strstr(name, " ");
                if (!name) {
                    i = 0;
                    break;
                }
                name++; // skip past the space
            }
            if (i != 0) {
                // log ("got blk name: %s (%s)", name, buffer);
                // if (strncmp (name, "\"External0 Whole Card\"", 16) == 0)
                if (strncmp(&name[1], part_name, len) == 0 &&
                    name[len + 1] == '\"') {
                    id = atoi(&buffer[3]); // skip past the initial "mtd"
                    // log ("External card in position %d", id);
                }
            }
        }

    if (f)
        fclose(f);

    return id;
}

/** creates a new mtd given a chardev number. So to open /dev/mtd4, use
an mtd_num of 4 */

mtd_info *mtd_new_chardev(int mtd_num, int readonly)
{
    char name[30];

    sprintf(name, "/dev/mtd%d", mtd_num);
    return mtd_new_filename(name, readonly);
}

/** creates a new mtd given a partition name, like "Internal0 Root Filesystem"
 */

mtd_info *mtd_new_partition_name(const char *part_name, int readonly)
{
    int mtd_num;

    mtd_num = mtd_find_part_name(part_name);
    if (mtd_num < 0) {
        fprintf(stderr, "Invalid MTD partition name: %s\n", part_name);
        return NULL;
    }

    return mtd_new_chardev(mtd_num, readonly);
}

/*
 * Creates a new mtd given a name. Automatically determines whether the name
 * is a number (chardev), a filename (starts with /) or a partition name.
 */
mtd_info *mtd_new_auto(const char *name, int readonly)
{
    int len, i;

    len = strlen(name);

    for (i = 0; i < len; i++)
        if (!isdigit(name[i]))
            break;

    if (i == len)
        return mtd_new_chardev(atoi(name), readonly);

    if (name[0] == '/')
        return mtd_new_filename(name, readonly);

    if (strncmp("mtd", name, 3) == 0) {
        char filename[64];
        sprintf(filename, "/dev/%s", name);
        return mtd_new_filename(filename, readonly);
    }

    return mtd_new_partition_name(name, readonly);
}

/** close an mtd partition */

int mtd_close(mtd_info *mtd)
{
    if (mtd->fd != -1) {
        DO_OP("mtd_close", close(mtd->fd));
        mtd->fd = -1;
    }
    return 0;
}

/** dispose of an mtd partition. Must be called when finished. Will return
an error code if something goes wrong, but will dispose of the mtd anyway */

int mtd_dispose(mtd_info *mtd)
{
    int err;

    err = mtd_close(mtd);
    mtd_free(mtd);
    return err;
}

int mtd_unlock_blocks(mtd_info *mtd, uint64_t start, int nblocks)
{
    return mtd_unlock(mtd, start, nblocks * mtd->info.erasesize);
}

int mtd_lock_blocks(mtd_info *mtd, uint64_t start, int nblocks)
{
    return mtd_lock(mtd, start, nblocks * mtd->info.erasesize);
}

int mtd_unlock(mtd_info *mtd, int start, int nbytes)
{
    struct erase_info_user unlock;
    unlock.start = start;
    unlock.length = nbytes;

    if (mtd->locking) {
        DO_OP("mtd_unlock", ioctl(mtd->fd, MEMUNLOCK, &unlock));
        if (mtd->err)
            mtd->locking = 0;
    }

    return mtd->err;
}

int mtd_lock(mtd_info *mtd, uint64_t start, int nbytes)
{
    struct erase_info_user lock;
    lock.start = start;
    lock.length = nbytes;

    if (mtd->locking) {
        DO_OP("mtd_lock", ioctl(mtd->fd, MEMLOCK, &lock));
        if (mtd->err)
            mtd->locking = 0;
    }

    return mtd->err;
}

/** erase sequential blocks of an mtd:

    \param mtd     the mtd to erase
    \param start   the start address
    \param nbytes  number of bytes to erase

    \returns -ve on error, 0 on success */

int mtd_erase_bytes(mtd_info *mtd, uint64_t start, uint64_t nbytes)
{
    struct erase_info_user erase;
    if (mtd->ioctl_64) {
        struct erase_info_user64 erase;

        erase.start = start;
        erase.length = nbytes;
        DO_OP("mtd_erase_bytes", ioctl(mtd->fd, MEMERASE64, &erase));

        /* If it failed, and we hadn't yet checked that they were supported,
         * then continue on with the old mechanism */
        if (mtd->err == -ENOTTY && mtd->ioctl_64 == -1)
            mtd->ioctl_64 = 0;
        else {
            if (mtd->err == 0)
                mtd->ioctl_64 = 1;
            return mtd->err;
        }
    }

    erase.start = start;
    erase.length = nbytes;
    DO_OP("mtd_erase_bytes", ioctl(mtd->fd, MEMERASE, &erase));
    return mtd->err;
}

/** erase sequential blocks of an mtd:

    \param mtd     the mtd to erase
    \param start   the start address
    \param nblocks number of blocks to erase

    \returns -ve on error, 0 on success */

int mtd_blocks_erase(mtd_info *mtd, uint64_t start, int nblocks)
{
    return mtd_erase_bytes(mtd, start, nblocks * mtd->info.erasesize);
}

int mtd_blocks_erase_nobad(mtd_info *mtd, uint64_t start, int nblocks)
{
    uint64_t len = (uint64_t)nblocks * (uint64_t)mtd->info.erasesize;
    int ret;
    for (; start + mtd->info.erasesize <= len; start += mtd->info.erasesize) {
        if (!mtd_block_is_bad(mtd, start)) {
            ret = mtd_erase_bytes(mtd, start, mtd->info.erasesize);
            if (ret < 0)
                return ret;
        }
    }
    return 0;
}

/** seek to a position in the mtd, which must be a multiple of the page
size */

uint64_t mtd_lseek(mtd_info *mtd, uint64_t start, int whence)
{
    uint64_t retval = lseek64(mtd->fd, start, whence);
    if (retval == (uint64_t)-1)
        DO_OP("mtd_lseek", -1);
    return retval;
}

/** read some bytes from the mtd - must read a multiple of the page size

   \returns number of bytes written or -ve on error (as 'read') */

int mtd_read(mtd_info *mtd, char *buff, int size)
{
    DO_OP("mtd_read", read(mtd->fd, buff, size));
    return mtd->err;
}

/** write some bytes to the mtd - must write a multiple of the page size

   \returns number of bytes written or -ve on error (as 'write') */

int mtd_write(mtd_info *mtd, const char *buff, int size)
{
    DO_OP("mtd_write", write(mtd->fd, buff, size));
    return mtd->err;
}

/** write a page to nand. Does not write the OOB data itself, so you do not
need to include OOB data in the data buffer you pass in. But if ECC is on,
then it will calculate and write ECC data to the OOB area

    \param mtd        the mtd to write to
    \param start      the start address to write to
    \param data       data to write (must be a page in length)

    \returns 0 on success, -ve on error or -ENOSPC if not all data written */

int mtd_page_write(mtd_info *mtd, uint64_t start, const char *data)
{
    DO_OP("mtd_page_write", pwrite64(mtd->fd, data, mtd->page_size, start));
    if (mtd->err != mtd->page_size)
        return mtd_set_error(mtd, "mtd_page_write", -ENOSPC,
                             "pwrite of %d bytes wrote only %d",
                             mtd->page_size, mtd->err);
    return mtd->err;
}

/** read a page from nand. Does not read the OOB data so you do not need
to allow space for this in your buffer

   \param mtd      the mtd to read from
   \param start    the start address to read from
   \param data     the buffer to place the data read

   \returns 0 on success, -ve on error or -ENOSPC if not all data read */

int mtd_page_read(mtd_info *mtd, uint64_t start, char *data)
{
    DO_OP("mtd_page_read", pread64(mtd->fd, data, mtd->page_size, start));
    if (mtd->err != mtd->page_size)
        return mtd_set_error(mtd, "mtd_page_read", -ENOSPC,
                             "pread of %d bytes wrote only %d",
                             mtd->page_size, mtd->err);
    return 0;
}

/** write a block to nand. Does not write the OOB data itself, so you do not
need to include OOB data in the data buffer you pass in. But if ECC is on,
then it will calculate and write ECC data to the OOB area of each page.

    \param mtd        the mtd to write to
    \param start      the start address to write to
    \param data       data to write (must be a block in length)

    \returns number of bytes written on success, -ve on error or -ENOSPC
    if not all data written */

int mtd_block_write(mtd_info *mtd, uint64_t start, const char *data)
{
    DO_OP("mtd_block_write", pwrite64(mtd->fd, data, mtd->block_size, start));
    if (mtd->err != mtd->block_size)
        return mtd_set_error(mtd, "mtd_block_write", -ENOSPC,
                             "pwrite of %d bytes wrote only %d",
                             mtd->block_size, mtd->err);
    return mtd->err;
}

/** read a block from nand. Does not read the OOB data so you do not need
to allow space for this in your buffer

   \param mtd      the mtd to read from
   \param start    the start address to read from
   \param data     the buffer to place the data read

   \returns number of bytes read on success, -ve on error or -ENOSPC if
   not all data read */

int mtd_block_read(mtd_info *mtd, uint64_t start, char *data)
{
    DO_OP("mtd_block_read", pread64(mtd->fd, data, mtd->block_size, start));
    if (mtd->err != mtd->block_size)
        return mtd_set_error(mtd, "mtd_block_read", -ENOSPC,
                             "pread of %d bytes wrote only %d",
                             mtd->block_size, mtd->err);
    return mtd->err;
}

/* read the out of band data at a particular position.

   \param mtd      mtd to read
   \param pos      position of page whose OOB data is to be read
                       (point to the start of the data page, not the
                        OOB data)
   \param oob      oob data will be placed here

   \returns -ve on error,
            number of bytes read on success */

int mtd_page_read_oob(mtd_info *mtd, uint64_t pos, char *oob)
{
    struct mtd_oob_buf oob_info;
    if (mtd->ioctl_64) {
        struct mtd_oob_buf64 oob_info;

        oob_info.length = mtd->info.oobsize;
        oob_info.start = pos;
        oob_info.usr_ptr = (uintptr_t)oob;

        DO_OP("mtd_page_read_oob", ioctl(mtd->fd, MEMREADOOB64, &oob_info));

        if (mtd->err == -ENOTTY && mtd->ioctl_64 == -1)
            mtd->ioctl_64 = 0;
        else {
            if (mtd->err == 0)
                mtd->ioctl_64 = 1;
            return mtd->err;
        }
    }

    oob_info.length = mtd->info.oobsize;
    oob_info.start = pos;
    oob_info.ptr = (unsigned char *)oob;

    DO_OP("mtd_page_read_oob", ioctl(mtd->fd, MEMREADOOB, &oob_info));
    return mtd->err;
}

/* write the out of band data at a particular position.

   \param mtd      mtd to read
   \param pos      position of page whose OOB data is to be written
                       (point to the start of the data page, not the
                        OOB data)
   \param oob      oob data to write

   \returns -ve on error,
            number of bytes written on success */

int mtd_page_write_oob(mtd_info *mtd, uint64_t pos, const char *oob)
{
    struct mtd_oob_buf oob_info;

    if (mtd->ioctl_64) {
        struct mtd_oob_buf64 oob_info;

        oob_info.length = mtd->info.oobsize;
        oob_info.start = pos;
        oob_info.usr_ptr = (uintptr_t)oob;

        DO_OP("mtd_page_write_oob", ioctl(mtd->fd, MEMWRITEOOB64, &oob_info));

        /* If it failed, and we hadn't yet checked that they were supported,
         * then continue on with the old mechanism */
        if (mtd->err == -ENOTTY && mtd->ioctl_64 == -1)
            mtd->ioctl_64 = 0;
        else {
            if (mtd->err == 0)
                mtd->ioctl_64 = 1;
            return mtd->err;
        }
    }
    /* Old mechanism */

    oob_info.length = mtd->info.oobsize;
    oob_info.start = pos;
    oob_info.ptr = (unsigned char *)oob;

    DO_OP("mtd_page_write_oob", ioctl(mtd->fd, MEMWRITEOOB, &oob_info));
    return mtd->err;
}

/** returns the number of regions in an mtd */

int mtd_region_count(mtd_info *mtd)
{
    int count;

    DO_OP("mtd_region_count", ioctl(mtd->fd, MEMGETREGIONCOUNT, &count));
    return count;
}

/* returns information about an mtd region

   \param mtd         mtd to check
   \param region      region index to check (0...numregions-1)
   \param offset      returns offset of region
   \param erasesize   returns erasesize of region
   \param numblocks   return numbers of blocks in region */

int mtd_region_info(mtd_info *mtd, uint32_t region, uint32_t *offset,
                    uint32_t *erasesize, uint32_t *numblocks)
{
    struct region_info_user reg;

    reg.regionindex = region;
    DO_OP("mtd_region_info", ioctl(mtd->fd, MEMGETREGIONINFO, &reg));
    assert(offset);
    assert(erasesize);
    assert(numblocks);
    *offset = reg.offset;
    *erasesize = reg.erasesize;
    *numblocks = reg.numblocks;
    return 0;
}

/** returns the type of an mtd

   \returns the mtd type:

         MTD_ABSENT    - not present
         MTD_RAM       - is RAM
         MTD_ROM       - is simple ROM
         MTD_NORFLASH  - is NOR flash
         MTD_NANDFLASH - is NAND flash
         MTD_PEROM     - is programmable erasable ROM
         MTD_OTHER     - something else
         MTD_UNKNOWN   - from another planet? */

int mtd_type(mtd_info *mtd)
{
    return mtd->info.type;
}

/** returns a string representing the mtd type */

char *mtd_type_name(mtd_info *mtd)
{
    switch (mtd->info.type) {
    case MTD_ABSENT:
        return "absent";
    case MTD_RAM:
        return "ram";
    case MTD_ROM:
        return "rom";
    case MTD_NORFLASH:
        return "norflash";
    case MTD_NANDFLASH:
        return "nandflash";
    case MTD_DATAFLASH:
        return "dataflash";
    case MTD_MLCNANDFLASH:
        return "mlcnandflash";
    default:
        return "unknown type";
    }
}

char *mtd_partition_name(mtd_info *mtd)
{
    char *mtd_name = strstr(mtd->fname, "mtd");
    char buffer[200];
    FILE *f;

    // scan /proc/mtd looking for the name
    f = fopen("/proc/mtd", "r");
    if (f)
        while (!feof(f)) {
            if (fgets(buffer, sizeof(buffer), f) == NULL)
                break;

            if (strncmp(buffer, mtd_name, strlen(mtd_name)) == 0 &&
                buffer[strlen(mtd_name)] == ':') {
                char *start = strchr(buffer, '\"');
                char *end = start ? strchr(start + 1, '\"') : NULL;

                if (start && end) {
                    int len = end - start - 1;

                    strncpy(mtd->errmess, start + 1, len);
                    mtd->errmess[len] = '\0';
                    fclose(f);
                    return mtd->errmess;
                }
            }
        }

    fclose(f);

    return NULL;
}

/* returns a size converted to a string of the form "65536 (64K)"

   \param str      place to put string. If NULL then static memory will be
                   used, so in this case this function is not thread-safe.
   \param size     size */

char *mtd_sizestr(char *str, uint64_t x)
{
    int i;
    static char static_str[30];
    static const char *flags = "KMGT";
    char *s;

    if (!str)
        str = static_str;
    s = str;
    s += sprintf(s, "%" PRIu64 " ", x);
    for (i = 0; x >= 1024 && flags[i] != '\0'; i++)
        x /= 1024;
    i--;
    if (i >= 0)
        s += sprintf(s, "(%" PRIu64 "%c)", x, flags[i]);
    return str;
}

/** returns the mtd flags

   \returns flags
      MTD_CLEAR_BITS          Bits can be cleared (flash)
      MTD_SET_BITS            Bits can be set
      MTD_ERASEABLE           Has an erase function
      MTD_WRITEB_WRITEABLE    Direct IO is possible
      MTD_VOLATILE            Set for RAMs
      MTD_XIP                 eXecute-In-Place possible
      MTD_OOB                 Out-of-band data (NAND flash)
      MTD_ECC                 Device capable of automatic ECC */

int mtd_flags(mtd_info *mtd)
{
    return mtd->info.flags;
}

/** returns a string representing the mtd flags */

char *mtd_flags_name(mtd_info *mtd)
{
    char *s = mtd->errmess; // use this as a buffer
    int i;
    int first = 1;
    static struct {
        const char *name;
        int value;
    } flags[] = {//{ "MTD_CLEAR_BITS", MTD_CLEAR_BITS },
                 //{ "MTD_SET_BITS", MTD_SET_BITS },
                 //{ "MTD_ERASEABLE", MTD_ERASEABLE },
                 //{ "MTD_WRITEB_WRITEABLE", MTD_WRITEB_WRITEABLE },
                 //{ "MTD_VOLATILE", MTD_VOLATILE },
                 //{ "MTD_XIP", MTD_XIP },
                 //{ "MTD_OOB", MTD_OOB },
                 //{ "MTD_ECC", MTD_ECC },
                 {"MTD_WRITEABLE", MTD_WRITEABLE},
                 {"MTD_BIT_WRITEABLE", MTD_BIT_WRITEABLE},
                 {"MTD_NO_ERASE", MTD_NO_ERASE},
                 {NULL, -1}};

    if (mtd->info.flags == MTD_CAP_ROM)
        s += sprintf(s, "MTD_CAP_ROM: ");
    else if (mtd->info.flags == MTD_CAP_RAM)
        s += sprintf(s, "MTD_CAP_RAM: ");
    else if (mtd->info.flags == MTD_CAP_NORFLASH)
        s += sprintf(s, "MTD_CAP_NORFLASH: ");
    else if (mtd->info.flags == MTD_CAP_NANDFLASH)
        s += sprintf(s, "MTD_CAP_NANDFLASH: ");

    for (i = 0; flags[i].name != NULL; i++)
        if (mtd->info.flags & flags[i].value) {
            s += sprintf(s, "%s%s", first ? "" : " | ", flags[i].name);
            first = 0;
        }

    s += sprintf(s, " 0x%x", mtd->info.flags);
    return mtd->errmess;
}

/** returns the size of a device */

uint64_t mtd_size(mtd_info *mtd)
{
    return mtd->size;
}

/** returns the erase size (= block size) of a device */

unsigned mtd_erasesize(mtd_info *mtd)
{
    return mtd->info.erasesize;
}

/** returns the erase size (= block size) of a device */

unsigned mtd_blocksize(mtd_info *mtd)
{
    return mtd->info.erasesize;
}

/** returns the number of blocks in device */

unsigned mtd_blockcount(mtd_info *mtd)
{
    return mtd->block_count;
}

/** returns the number of pages in a device */

unsigned mtd_pagecount(mtd_info *mtd)
{
    return mtd->page_count;
}

/** returns the page data size (= writesize) of a device. Note this excludes
any out of band data */

unsigned mtd_pagesize(mtd_info *mtd)
{
    return mtd->page_size;
}

/** returns the size of the out of band data for the device */

int mtd_oobsize(mtd_info *mtd)
{
    return mtd->info.oobsize;
}

int mtd_oobavail(mtd_info *mtd)
{
    struct nand_ecclayout_user layout;

    if (DO_OP("eccgetlayout", ioctl(mtd->fd, ECCGETLAYOUT, &layout)) < 0)
        return mtd->err;

    return layout.oobavail;
}

int mtd_eccmode(mtd_info *mtd)
{
    struct nand_oobinfo oob;

    int r = ioctl(mtd->fd, MEMGETOOBSEL, &oob);
    if (r < 0 && errno == EOPNOTSUPP) // if it isn't supported, then ignore
        return 0;
    if (r < 0) {
        r = -errno;
        DO_OP("mtd_eccmode", r);
    }
    return oob.useecc;
}

char *mtd_eccmode_name(mtd_info *mtd)
{
    int mode;

    mode = mtd_eccmode(mtd);
    switch (mode) {
    case MTD_NANDECC_AUTOPLACE:
        return "Auto-place";
    case MTD_NANDECC_OFF:
        return "Off";
    case MTD_NANDECC_PLACE:
        return "Place";
    case MTD_NANDECC_PLACEONLY:
        return "Place only";
    case MTD_NANDECC_AUTOPL_USR:
        return "User auto-place";
    }
    fprintf(stderr, "Unknown ECC mode %d\n", mode);

    return "<unknown>";
}

char *mtd_filename(mtd_info *mtd)
{
    return mtd->fname;
}

/*************************** bad blocks ***************************/

int mtd_bad_block_count(mtd_info *mtd)
{
    uint64_t offs;
    int count = 0;
    int ret;

    for (offs = 0; offs < mtd_size(mtd); offs += mtd_blocksize(mtd)) {
        ret = mtd_block_is_bad(mtd, offs);
        if (ret < 0)
            return ret;
        if (ret > 0)
            count++;
    }

    return count;
}

/** checks if a block is good or bad.

   \param mtd      the mtd to check
   \param offs     the offset to check

   \returns 0 if a block is good, 1 if bad, -ve for an error */

int mtd_block_is_bad(mtd_info *mtd, uint64_t offs)
{
    int r = ioctl(mtd->fd, MEMGETBADBLOCK, &offs);
    if (r < 0 &&
        errno ==
            EOPNOTSUPP) // if it isn't supported, then the block isn't bad
        r = 0;
    if (r < 0) {
        r = -errno;
        DO_OP("mtd_block_is_bad", r);
    }
    return r;
}

/** marks a block bad

   \param mtd     the mtd to update
   \param offs    the offset to update

   \returns -ve on error, 0 on success */

int mtd_block_mark_bad(mtd_info *mtd, uint64_t offs)
{
    // mask off the page bits
    uint64_t mask = mtd_blocksize(mtd);
    mask = ~(mask - 1);

    if (offs != (offs & mask))
        fprintf(stderr,
                "%s(): offs 0x%" PRIx64 " -> 0x%" PRIx64 " (0x%" PRIx64 ")\n",
                __FUNCTION__, offs, offs & mask, mask);

    offs = offs & mask;
    DO_OP("mtd_block_mark_bad", ioctl(mtd->fd, MEMSETBADBLOCK, &offs));

    if (mtd->err < 0)
        return mtd->err;

    return mtd->err;
}

/** marks a block bad and check it worked

   \param mtd     the mtd to update
   \param offs    the offset to update

   \returns -ve on error, 0 on success, -EIO if a read-back indicates it
   didn't work */

int mtd_block_mark_bad_check(mtd_info *mtd, uint64_t offs)
{
    int ret;

    ret = mtd_block_mark_bad(mtd, offs);
    if (ret < 0)
        return ret;

    /* Check using the in memory bbt */
    ret = mtd_block_is_bad(mtd, offs);
    if (ret <= 0) // block is not bad!
        return mtd_set_error(mtd, "mtd_block_mark_bad_check",
                             ret < 0 ? ret : -EIO,
                             "Marking block bad failed at %" PRIx64 "", offs);

    /* Check using the actual flash data */
    ret = mtd_block_is_bad_raw(mtd, offs);
    if (ret <= 0) // block is not bad!
        return mtd_set_error(
            mtd, "mtd_block_mark_bad_check", ret < 0 ? ret : -EIO,
            "Marking block bad raw failed at %" PRIx64 " (raw)", offs);

    return 0;
}

/* starting from the block after the given offset, finds the next good block
(which is not marked bad)

   \param mtd      mtd to search
   \param pos      starts at the block after this one, returns pos updated
                   to point to the next good block found

   \returns -ve on error
            0 on success
            1 if no more good blocks */

int mtd_block_find_next_good(mtd_info *mtd, uint64_t *pos)
{
    int ret = 1;

    while (ret == 1 && mtd_block_next(mtd, pos))
        ret = mtd_block_is_bad(mtd, *pos);
    return ret;
}

/* starting from the block after the given offset, finds the next good block
(which is not marked bad) and writes the given block of data to it. If that
write fails, it marks the block bad and continues looking for a good block
to write to.

Updates offs to the position that the block was written to.

Terminates when:

 - the block is successfully written (iwc returns number of bytes written)
 - gets to end of mtd (returns 0)
 - 20 write attempts have been made (returns -EDQUOT) */

int mtd_block_write_next_good(mtd_info *mtd, uint64_t *offs, char *buffer)
{
    int bad_blocks = 0;
    int ret;

    do {
        // find a spot to write it
        ret = mtd_block_find_next_good(mtd, offs);
        if (ret < 0) // error
            return ret;
        if (ret == 1)
            return 0; // ran out of good blocks

        // write it (returns number of bytes written)
        ret = mtd_block_write(mtd, *offs, buffer);
        // printf ("mtd_block_write_next_good: offs=%" PRIx64 ", ret=%d\n",
        // *offs, ret);

        // if it failed, mark the block bad and continue
        if (ret < 0) {
            if (++bad_blocks == 20) {
                mtd_set_error(mtd, "mtd_block_write_next_good", -EDQUOT,
                              "Marked bad blocks in this write "
                              "exceeded limit of %d",
                              bad_blocks);
                return -1;
            }
            mtd_block_mark_bad(mtd, *offs);
        }
    } while (ret < 0);
    return ret;
}

/** reads the next good block started from the block after 'offs'. Bad blocks
are skipped. The data is placed in buff, which must be able to hold a block
of data (mtd_blocksize()).

Updates offs to the position of the good block read.

Terminates when:

 - error (returns -ve)
 - the block is successfully read (iwc returns number of bytes read)
 - gets to end of mtd (returns 0 and no data in buff) */

int mtd_block_read_next_good(mtd_info *mtd, uint64_t *offs, char *buff)
{
    int ret;

    ret = mtd_block_find_next_good(mtd, offs);
    if (ret < 0) // eof or error
        return ret;
    if (ret == 1)
        return 0; // ran out of good blocks

    // read the block
    return mtd_block_read(mtd, *offs, buff);
}

/** returns the raw bad block byte from a block. This byte will normally
be 0xff for a good block, and something else for a bad block (often 0).

   \param mtd      mtd to check
   \param pos      position of block to check

   \returns  -ve on error
             0 if good
             1 if bad
*/

int mtd_block_is_bad_raw(mtd_info *mtd, uint64_t pos)
{
    char oob[mtd->info.oobsize];
    int ret;
    int bad_pos = mtd->page_size > 512 ? NAND_LARGE_BADBLOCK_POS
                                       : NAND_SMALL_BADBLOCK_POS;

    ret = mtd_page_read_oob(mtd, pos, oob);
    if (ret < 0)
        return ret;
    if (oob[bad_pos] != 0xff)
        return 1;

    /* Scan the second page in, as the mtd layer does */
    ret = mtd_page_read_oob(mtd, pos + mtd->page_size, oob);
    if (ret < 0)
        return ret;
    if (oob[bad_pos] != 0xff)
        return 1;

    return 0;
}

/** returns whether the block is considered free (nothing written to its first
   page)

   \param mtd      mtd to check
   \param pos      position of block to check

   \returns  -ve on error
             0 if in used
             1 if free
*/
int mtd_block_is_free(mtd_info *mtd, uint64_t pos)
{
    char oob[mtd->info.oobsize];
    int ret;
    int i;

    ret = mtd_page_read_oob(mtd, pos, oob);
    if (ret < 0)
        return ret;

    for (i = 0; i < mtd->info.oobsize; i++)
        if (oob[i] != 0xff)
            return 0;

    return 1;
}

/* starting from the block after the given offset, finds the next free block
    (whose first oob entry is all empty)

   \param mtd      mtd to search
   \param pos      starts at the block after this one, returns pos updated
                   to point to the next good block found

   \returns -ve on error
            0 on success
            1 if no more good blocks */

int mtd_block_find_next_free(mtd_info *mtd, uint64_t *posp)
{
    int ret = 1;
    uint64_t pos;

    for (pos = *posp; pos < mtd_size(mtd); pos += mtd_blocksize(mtd)) {
        ret = mtd_block_is_free(mtd, pos);
        if (ret < 0)
            return ret;
        if (ret > 0) {
            *posp = pos;
            return 0;
        }
    }

    return 1; // none found
}

/*************************** positioning ************************/

/** position the given pointer before the start of the mtd device. Call
mtd_next_block () to find the first block

   \returns 1 if ok, 0 if at end of device */

int mtd_start(mtd_info *mtd, uint64_t *pos)
{
    *pos = -1;
    return mtd->size > 0;
}

/* position the given pointer at the start of the next block

   \returns 1 if ok, 0 if at end of device */

int mtd_block_next(mtd_info *mtd, uint64_t *pos)
{
    if (*pos & 1)
        (*pos)++;
    else
        *pos += mtd->info.erasesize;
    return *pos < mtd->size;
}

/** position the given pointer before the start of the first page of a block.
After this, call mtd_page_next () to find the first page (or mtd_block_next()
to find the start of the block)

   \returns 1 if ok, 0 if at end of device */

int mtd_block_start(mtd_info *mtd, uint64_t block, uint64_t *pos)
{
    *pos = block - 1;
    return block < mtd->size;
}

/* position the given pointer at the start of the next page. This function
should be called after mtd_block_start() or mtd_start() to set 'pos' to
the first page (and return 1). After that it will move pos to the next page
on each call, returning 1 each time. After the last page it will return 0
meaning no more pages. If you then call mtd_page_next() one more time, you
will move into the next block and it will start returning 1 again.

Usage is:

   for (mtd_block_start (mtd, block, &pos); mtd_page_next (mtd, &pos); )
      // process each page in the block

or:
   for (mtd_start (mtd, &pos); !mtd_eof (mtd, &pos); )
      {
      // process block
      while (mtd_page_next (mtd, &pos))
         // process each page in the block
      }

   \returns 1 if ok, 0 if at end of block */

int mtd_page_next(mtd_info *mtd, uint64_t *pos)
{
    uint64_t newpos = *pos;

    if (newpos & 1) // assume this means we are just starting
        newpos++;
    else {
        newpos += mtd_pagesize(mtd);
        if ((newpos ^ *pos) & mtd->block_mask) {
            // we are at the end of a block
            *pos = newpos - 1;
            return 0;
        }
    }
    *pos = newpos;
    return *pos < mtd->size;
}

/** checks for the end of an mtd device

   \returns 1 if at eof, 0 otherwise */

int mtd_eof(mtd_info *mtd, uint64_t pos)
{
    return pos >= mtd->size;
}

/** returns the absolute block number of a given mtd device position,
numbering the blocks from 0 (first block in the device)

   \returns   block number, or -1 if outside the device */

int mtd_blocknum(mtd_info *mtd, uint64_t pos)
{
    return pos >> mtd->block_shift;
}

/** returns the absolute page number of a given mtd device position,
numbering the page from 0 (first page in the first block)

   \returns   block number, or -1 if outside the device */

int mtd_pagenum(mtd_info *mtd, uint64_t pos)
{
    return pos >> mtd->page_shift;
}

/**************************** multiple card handling *******************/

int mtd_init(void)
{
    return 0;
}

/*
 * High level functions
 */
int mtd_erase_partition(const char *mtd_part, progress_callback progress)
{
    unsigned block_size;
    uint64_t length;
    loff_t offset;
    mtd_info *mtd;
    int ret;

    mtd = mtd_new_auto(mtd_part, 0);
    if (!mtd)
        return -ENODEV;

    length = mtd_size(mtd);
    block_size = mtd_blocksize(mtd);

    if (progress)
        progress("Erasing MTD", 0, length);

    for (offset = 0; offset + block_size <= length; offset += block_size) {
        if (!mtd_block_is_bad(mtd, offset)) {
            ret = mtd_blocks_erase(mtd, offset, 1);
            if (ret) {
                mtd_dispose(mtd);
                return ret < 0 ? ret : -EIO;
            }
        }

        if (progress)
            progress("Erasing MTD", offset, length);
    }

    if (progress)
        progress("Erasing MTD", length, length);
    mtd_dispose(mtd);
    return 0;
}

static int mtd_write_block(mtd_info *mtd, loff_t offset, const char *data,
                           size_t length)
{
    unsigned block_size;
    char *block = NULL;
    ssize_t bytes;
    int err;

    err = mtd_lseek(mtd, offset, SEEK_SET);
    if (err < 0)
        return err < 0 ? err : -ESPIPE;

    block_size = mtd_blocksize(mtd);
    if (length < block_size) {
        /*
         * Writes must be block_size aligned, so if we are writing less
         * (ie last chunk of file) then temporarily allocate a block_size
         * aligned data area. We clear the extra space to zero.
         */
        block = malloc(block_size);
        if (!block)
            return -ENOMEM;

        memset(block, 0, block_size);
        memcpy(block, data, length);
    }

    bytes = mtd_write(mtd, block ? block : data, block_size);
    if (block)
        free(block);
    if (bytes < block_size)
        return bytes < 0 ? bytes : -EIO;

    return 0;
}

static int mtd_verify_block(mtd_info *mtd, loff_t offset, char *data,
                            size_t length)
{
    unsigned block_size;
    ssize_t bytes;
    char *buffer;
    int err;

    block_size = mtd_blocksize(mtd);
    buffer = malloc(block_size);
    if (!buffer)
        return -ENOMEM;

    /* Read the block back to verify it */
    err = mtd_lseek(mtd, offset, SEEK_SET);
    if (err < 0) {
        free(buffer);
        return err < 0 ? err : -ESPIPE;
    }

    /* Read back the block we just wrote */
    bytes = mtd_read(mtd, buffer, block_size);
    if (bytes < block_size) {
        free(buffer);
        return bytes < 0 ? bytes : -EIO;
    }

    /* Check if the block read matches what was written */
    if (memcmp(buffer, data, length) != 0) {
        free(buffer);
        return -EAGAIN;
    }

    /* Block matches data */
    free(buffer);
    return 0;
}

int mtd_write_file(const char *file, const char *mtd_partition,
                   int max_verify_failures, progress_callback progress)
{
    ssize_t count, bytes_written;
    unsigned block_size;
    size_t file_size;
    mtd_info *mtd;
    loff_t offset;
    char *image;
    int err;
    FILE *fd;
    struct stat file_stat;

    mtd = mtd_new_auto(mtd_partition, 0);
    if (!mtd) {
        err = -ENODEV;
        goto fail;
    }
    block_size = mtd_blocksize(mtd);

    fd = fopen(file, "r");
    if (!fd) {
        err = -errno;
        goto fail_dispose_mtd;
    }

    if (stat(file, &file_stat) < 0) {
        err = -errno;
        goto fail_free_fd;
    }
    file_size = file_stat.st_size;
    image = (char *)malloc(block_size);
    if (!image) {
        err = -ENOMEM;
        goto fail_free_fd;
    }

    if (progress)
        progress("Writing to MTD", 0, file_size);

    printf("MTD: Writing file '%s' to '%s'. size=%lld/%lld block_size=%d\n",
           file, mtd_partition, (long long)file_size,
           (long long)mtd_size(mtd), block_size);

    if (file_size > mtd_size(mtd)) {
        fprintf(stderr,
                "Unable to write '%s' to '%s' - source file is larger (%lld) "
                "than partition size (%lld)\n",
                file, mtd_partition, (long long)file_size,
                (long long)mtd_size(mtd));
        err = -ENOSPC;
        goto fail_free_image;
    }

    offset = 0;
    bytes_written = 0;
    while (bytes_written < file_size) {
        /* Skip bad blocks */
        while (mtd_block_is_bad(mtd, offset)) {
            if (mtd_eof(mtd, offset)) {
                /* Too many blocks - No room left to write file */
                err = -ENOSPC;
                goto fail_free_image;
            }

            offset += block_size;
        }

        err = mtd_blocks_erase(mtd, offset, 1);
        if (err)
            goto fail_free_image;
        /* Write a block */
        count = min(block_size, file_size - bytes_written);
        if (fseek(fd, bytes_written, SEEK_SET) < 0)
            goto fail_free_image;
        err = fread(image, 1, count, fd);
        if (err != count)
            goto fail_free_image;
        err = mtd_write_block(mtd, offset, image, count);
        if (err)
            goto fail_free_image;

        err = mtd_verify_block(mtd, offset, image, count);
        if (err) {
            fprintf(stderr, "Failed to verify block @ 0x%llx on %s: %d\n",
                    (long long)offset, mtd_partition, err);
            if (err != -EAGAIN)
                goto fail_free_image;
            if (max_verify_failures > 0) {
                fprintf(stderr, "Retrying block @ 0x%llx [%d retries left]\n",
                        (long long)offset, max_verify_failures);
                max_verify_failures--;
                continue;
            }

            /* Block failed to read back correctly, mark it bad */
            err = mtd_block_mark_bad(mtd, offset);
            if (err) {
                err = err < 0 ? err : -EIO;
                goto fail_free_image;
            }
            continue;
        }

        /* Block written successfully */
        bytes_written += block_size;
        offset += block_size;
        if (progress)
            progress("Writing to MTD", bytes_written, file_size);
    }

    /* Success */
    err = 0;
    if (progress)
        progress("Writing to MTD", file_size, file_size);

fail_free_image:
    free(image);
fail_free_fd:
    fclose(fd);
fail_dispose_mtd:
    mtd_dispose(mtd);
fail:
    return err;
}

int mtd_write_file_raw(const char *file, const char *mtd_partition,
                       progress_callback progress)
{
    ssize_t bytes_written;
    unsigned block_size;
    int size, i;
    mtd_info *mtd = NULL;
    uint8_t *buffer = NULL;
    uint8_t *oob_buffer = NULL;
    loff_t offset;
    int err;
    FILE *fp = NULL;

    /* Erase the MTD partition */
    err = mtd_erase_partition(mtd_partition, progress);
    if (err)
        goto fail;

    mtd = mtd_new_auto(mtd_partition, 0);
    if (!mtd) {
        err = -ENODEV;
        goto fail;
    }
    block_size = mtd_blocksize(mtd);
    buffer = malloc(mtd_pagesize(mtd));
    oob_buffer = malloc(mtd_oobsize(mtd));

    size = mtd_file_size(file);
    if (size < 0) {
        err = size;
        goto fail;
    }
    if (size % (mtd_pagesize(mtd) + mtd_oobsize(mtd))) {
        err = -EINVAL;
        fprintf(stderr, "Invalid file size: %d (%d/%d)\n", size,
                mtd_pagesize(mtd), mtd_oobsize(mtd));
        goto fail;
    }

    if ((fp = fopen(file, "rb")) == NULL) {
        err = -errno;
        goto fail;
    }

    if (progress) {
        progress("Writing to MTD", 0, size);
    }

    offset = 0;
    bytes_written = 0;
    while (!feof(fp)) {
        int len;
        /* Skip bad blocks */
        /* FIXME: Only need to do this on a block boundary, not for each page
         */
        while (mtd_block_is_bad(mtd, offset)) {
            if (mtd_eof(mtd, offset)) {
                /* Too many blocks - No room left to write file */
                err = -ENOSPC;
                goto fail;
            }

            offset += block_size;
        }
        /* Read page & oob data */
        len = fread(buffer, mtd_pagesize(mtd), 1, fp);
        /* If we reach EOF, then we're done */
        if (len == 0)
            break;
        if (len != 1) {
            fprintf(stderr,
                    "Unable to read data (offset=0x%" PRIx64 " pos=%ld)\n",
                    offset, ftell(fp));
            err = -EINVAL;
            goto fail;
        }
        if (fread(oob_buffer, mtd_oobsize(mtd), 1, fp) != 1) {
            fprintf(stderr,
                    "Unable to read oob (offset=0x%" PRIx64 " pos=%ld)\n",
                    offset, ftell(fp));
            err = -EINVAL;
            goto fail;
        }

        /* Write a page - try 5 times */
        for (i = 0; i < 5; i++) {
            if (mtd_lseek(mtd, offset, SEEK_SET) < 0) {
                fprintf(stderr, "Unable to seek to 0x%" PRIx64 "\n", offset);
                continue;
            }

            if (mtd_page_write(mtd, offset, (char *)buffer) !=
                mtd_pagesize(mtd)) {
                fprintf(stderr, "Unable to write page at 0x%" PRIx64 "\n",
                        offset);
                continue;
            }
            /* Write the oob */
            if (mtd_page_write_oob(mtd, offset, (char *)oob_buffer) < 0) {
                fprintf(stderr, "Unable to write oob at 0x%" PRIx64 "\n",
                        offset);
                continue;
            }
            break;
        }
        if (i == 5) {
            err = -EINVAL;
            goto fail;
        }
        /* FIXME: Should be verifying */

        bytes_written += mtd_pagesize(mtd);
        offset += mtd_pagesize(mtd);

        if (progress)
            progress("Writing to MTD", bytes_written, size);
    }

    /* Success */
    err = 0;
    if (progress)
        progress("Writing to MTD", size, size);

fail:
    if (mtd)
        mtd_dispose(mtd);
    if (buffer)
        free(buffer);
    if (oob_buffer)
        free(oob_buffer);
    return err;
}
