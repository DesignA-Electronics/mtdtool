/* ======================================================================
 *
 * File    : mtdtool.c
 * Project : Snapper
 * Author  : Andre Renaud
 * Company : Bluewater Systems Ltd
 *           http://www.bluewatersys.com
 *
 * Simple MTD tool for manipulating mtd character devices
 *
 * Licensed under GPLv2
 *
 * ======================================================================
 */

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "mtdlib.h"

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
    CMD_INFO,
    CMD_INFO_SCAN,
    CMD_ERASE,
    CMD_ERASEALL,
    CMD_QUICK_ERASE,
    CMD_WRITE,
    CMD_WRITE_RAW,
    CMD_READ,
    CMD_READ_RAW,
    CMD_READ_RAW_SKIP,
    CMD_DUMP,
    CMD_VERIFY,
    CMD_MARK_BAD,
    CMD_UNLOCK,
    CMD_LOCK,
    CMD_REWRITE,
    CMD_STRESS,

    CMD_UNKNOWN,
};

static int bad_block_skipping = 1;

static void usage(char *program)
{
    fprintf(stderr,
            "Usage: %s [options] <command> [args]\n"
            "\n"
            "Options:\n"
            "  --ignore_bad            Allow reading/writing of bad blocks "
            "(may fail)\n"
            "\n"
            "Commands:\n"
            "  --help\n"
            "      Show this help\n"
            "\n"
            "  --info <device>\n"
            "      Show information about the MTD partition\n"
            "\n"
            "  --info_scan <device>\n"
            "      Show information about the MTD partition, manually "
            "scanning for bad blocks\n"
            "\n"
            "  --erase <device> <offset> <length>\n"
            "      Erase a region of the partition\n"
            "\n"
            "  --force_erase <device> <offset> <length>\n"
            "      Erase a region, skipping bad-block checks\n"
            "\n"
            "  --eraseall <device>\n"
            "      Erase the entire partition\n"
            "\n"
            "  --force_eraseall <device>\n"
            "      Erase the entire partition, skipping bad-block checks\n"
            "\n"
            "  --quick_erase <device>\n"
            "      Erase only blocks that appear to be in use (may not be "
            "100%% accurate)\n"
            "\n"
            "  --write <device> <filename> [offset]\n"
            "      Erase and write a file to the partition\n"
            "\n"
            "  --write_raw <device> <filename> [offset]\n"
            "      Write a raw file (interleaved page+OOB data) to the "
            "partition\n"
            "\n"
            "  --read <device> <filename> <length> [offset]\n"
            "      Read data from the partition into a file\n"
            "\n"
            "  --read_raw <device> <filename> [length]\n"
            "      Read raw page+OOB data from the partition into a file\n"
            "\n"
            "  --read_raw_skip <device> <filename> [length]\n"
            "      Read raw page+OOB data, skipping fully-erased pages\n"
            "\n"
            "  --verify <device> <filename> [offset]\n"
            "      Verify that a file matches the contents of the partition\n"
            "\n"
            "  --rewrite <device> <filename> [offset]\n"
            "      Erase, write, then verify a file on the partition\n"
            "\n"
            "  --dump <device> <offset> [page_count]\n"
            "      Hex-dump pages including OOB starting at offset (default: "
            "1 page)\n"
            "\n"
            "  --markbad <device> <offset>\n"
            "      Forcibly mark the block at offset as bad\n"
            "\n"
            "  --unlock <device> [offset length]\n"
            "      Unlock the partition, or a region within it\n"
            "\n"
            "  --lock <device> <offset> <length>\n"
            "      Lock a region of the partition\n"
            "\n"
            "  --stress <device> <seconds>\n"
            "      Stress test: erase the entire partition, then randomly "
            "write and read\n"
            "      back blocks using per-block random seeds, reporting any "
            "errors\n",
            program);
}

static unsigned int get_msec(void)
{
    struct timeval _tv;
    gettimeofday(&_tv, NULL);
    return _tv.tv_sec * 1000 + _tv.tv_usec / 1000;
}

/* util_bytes_to_user: convert a number of bytes to a more useful string
representation. Eg 5653 becomes 5k. Similar (I hope) to the way the filer
does it */

static char *util_bytes_to_user(char *buff, uint64_t bytes)
{
    if (bytes < 0x1000)
        sprintf(buff, "%4" PRId64, bytes);
    else {
        bytes = (bytes + 512) >> 10;
        if (bytes < 0x1000)
            sprintf(buff, "%4" PRId64 "K", bytes);
        else {
            bytes = (bytes + 512) >> 10;
            sprintf(buff, "%4" PRId64 "M", bytes);
        }
    }
    return buff;
}

/* util_bytes_to_userf: convert a number of bytes to a more useful string
representation. Eg 5653 becomes 5k. Similar (I hope) to the way the filer
does it. Adds 2 decimal places*/

static char *util_bytes_to_userf(char *buff, uint64_t b)
{
    double bytes = b;

    if (bytes < 0x1000)
        sprintf(buff, "%4.0lf", bytes);
    else {
        bytes /= 1024;
        if (bytes < 0x1000)
            sprintf(buff, "%4.2lfK", bytes);
        else {
            bytes /= 1024;
            sprintf(buff, "%4.2lfM", bytes);
        }
    }
    return buff;
}

static void print_percentage(uint64_t amount, uint64_t total, int mb)
{
    static long long last_percentage =
        -1; // nasty hack to prevent it printing so often
    static unsigned int start = 0;
    long long percentage = (amount * 100) / total;
    char str1[20], str2[20];

    if (percentage < last_percentage || start == 0) // restart
        start = get_msec();
    if (percentage != last_percentage) {
        unsigned int dur = get_msec() - start;
        float rate = dur ? (float)amount / dur * 1000 : 0;
        printf("\r%3.3lld%%", percentage);
        if (mb)
            printf(" %s (%s/s)            ", util_bytes_to_user(str1, amount),
                   util_bytes_to_userf(str2, rate));
        // printf ("%s%3.3lld%%", percentage ? "\b\b\b\b": "", percentage);
        last_percentage = percentage;
        fflush(stdout);
        if (percentage == 100)
            printf("\n");
    }
}

static int erase_mtd(mtd_info *mtd, uint64_t start, uint64_t length,
                     int force)
{
    uint64_t real_start = start;

    if (!mtd)
        return -1;

    if (force) {
        fprintf(stderr, "Forced erases not supported\n");
        // return -1;
    }

    if (length == -1)
        length = mtd_size(mtd);
    for (; start + mtd_blocksize(mtd) <= length;
         start += mtd_blocksize(mtd)) {
        if (!force && mtd_block_is_bad(mtd, start))
            printf("Not erasing block at 0x%" PRIx64 " - it is bad\n", start);
        else if (mtd_blocks_erase(mtd, start, 1) != 0 && !force) {
            fprintf(stderr, "Failed to erase block at 0x%" PRIx64 ": %s\n",
                    start, mtd_strerror(mtd));
            goto error;
        }

        print_percentage(start - real_start, length, 1);
    }
    print_percentage(length, length, 1);

    // mark block 0 bad
    // we should only do this for xD, put it out for now
    //   printf ("Marking block 0 bad\n");
    //   mtd_block_mark_bad_check (mtd, 0);

    return 0;
error:
    return -1;
}

static int do_erase(char *device_name, uint64_t start, uint64_t length,
                    int force)
{
    mtd_info *mtd;
    int retval = 0;

    mtd = mtd_new_auto(device_name, 0);
    if (!mtd)
        return -1;

    retval = erase_mtd(mtd, start, length, force);

    mtd_dispose(mtd);
    return retval;
}

/** If the first page in the block is all 0xff oob, then consider the
 * block erased, and skip it
 */
static int do_quick_erase(char *device_name)
{
    mtd_info *mtd = NULL;
    int page;
    uint64_t offset;
    unsigned int size, blocksize;
    char oob[1024];
    char ff[1024];

    memset(ff, 0xff, sizeof(ff));

    mtd = mtd_new_auto(device_name, 0);
    if (!mtd)
        goto err;
    size = mtd_size(mtd);
    blocksize = mtd_blocksize(mtd);

    for (offset = 0; offset < size; offset += blocksize) {
        if (mtd_block_is_bad(mtd, offset)) {
            fprintf(stderr, "Skipped block at 0x%" PRIx64 " - bad\n", offset);
            continue;
        }
        for (page = 0; page < 2; page++) {
            if (mtd_page_read_oob(mtd, offset + mtd_pagesize(mtd) * page,
                                  oob) < 0)
                goto err;
            if (memcmp(oob, ff, mtd_oobsize(mtd)) != 0)
                if (mtd_blocks_erase(mtd, offset, 1) < 0)
                    goto err;
        }
        print_percentage(offset, size, 1);
    }

    mtd_dispose(mtd);
    return 0;
err:
    if (mtd)
        mtd_dispose(mtd);
    return -1;
}

static int do_unlock(char *device_name, uint64_t start, uint64_t length)
{
    mtd_info *mtd;
    int retval = 0;

    mtd = mtd_new_auto(device_name, 0);
    if (!mtd)
        return -1;

    if (start < 0)
        start = 0;
    if (length < 0)
        length = mtd_size(mtd);

    retval = mtd_unlock(mtd, start, length);

    mtd_dispose(mtd);
    return retval;
}

static int do_lock(char *device_name, uint64_t start, uint64_t length)
{
    mtd_info *mtd;
    int retval = 0;

    mtd = mtd_new_auto(device_name, 0);
    if (!mtd)
        return -1;

    retval = mtd_lock(mtd, start, length);

    mtd_dispose(mtd);
    return retval;
}

/* make some repeating data. The pattern is:

   0..255
   1..255, 0
   2..255, 0, 1
   3..255, 0..2
   etc.

   offset is the start position in the sequence */
static void make_data(char *buf, int offset, int size)
{
    int start;

    start = (offset >> 8) - 1;
    start += offset & 255;
    for (; size > 0; size--, start++, offset++) {
        if (!(offset & 255))
            start++;
        *buf++ = start;
    }
}

/** a file. This may be a read file or a pretend one (with pattern data) */

typedef struct file_info {
    char *fname;
    int size;
    int pos;
    FILE *fp;
    int is_special; // is a device
} file_info;

int file_new(file_info *file, char *fname, char *mode)
{
    struct stat buf;

    file->fname = fname;
    file->fp = NULL;
    file->is_special = 0;

    if (0 == strcmp(fname, "_count"))
        ;

    else if ((file->fp = fopen(fname, mode)) == NULL) {
        fprintf(stderr, "Unable to open '%s': %s\n", fname, strerror(errno));
        return -1;
    }

    // get (or make up) the file size
    if (file->fp) {
        fstat(fileno(file->fp), &buf);
        if (S_ISCHR(buf.st_mode)) {
            file->size = 500 * 1024 * 1024;
            file->is_special = 1;
        } else
            file->size = buf.st_size;
    } else
        file->size = 64 * 1024 * 1024;

    // we are at the start of the file
    file->pos = 0;
    return 0;
}

static int file_eof(file_info *file)
{
    return file->fp && !file->is_special ? feof(file->fp)
                                         : file->pos < file->size;
}

static int file_read(file_info *file, char *buf, int want)
{
    int len;

    if (file->fp) {
        len = fread(buf, 1, want, file->fp);
        file->pos = ftell(file->fp);
    } else {
        make_data(buf, file->pos, want);
        file->pos += want;
        len = want;
    }
    if (len < want)
        memset(&buf[len], 0xff, want - len);

    return len;
}

#if 0
static int file_seek (file_info *file, int skip)
{
   int retval = 0;

   file->pos = skip;
   if (file->pos > file->size)
      file->pos = file->size;
   if (file->fp)
   {
      retval = fseek (file->fp, file->pos, SEEK_SET);
      if (retval < 0)
         fprintf (stderr, "Unable to seek %s to %d: %s\n", file->fname, skip, strerror (errno));
   }
   return retval;
}
#endif

static void file_close(file_info *file)
{
    if (file->fp)
        fclose(file->fp);
}

static int do_write(char *device_name, char *filename, uint64_t offset)
{
    mtd_info *mtd = NULL;
    int retval = 0;
    char *buffer = NULL;
    file_info file;
    int write_size;

    mtd = mtd_new_auto(device_name, 0);
    if (!mtd) {
        retval = -1;
        goto done;
    }

    retval = file_new(&file, filename, "rb");
    if (retval < 0)
        goto done;

    // write_size = mtd_pagesize(mtd);
    //  we want to do large writes
    write_size = mtd_blocksize(mtd);

    /* Write size is 1 for NOR/SPI devices, in which case we can do the writes
     * in blocks
     */
    if (write_size == 1)
        write_size = mtd_blocksize(mtd);

    buffer = malloc(write_size);
    if (!buffer) {
        fprintf(stderr, "Unable to allocate buffer: %s\n", strerror(errno));
        retval = -1;
        goto done;
    }

    while (!file_eof(&file)) {
        int len;

        while (bad_block_skipping && mtd_block_is_bad(mtd, offset) &&
               !mtd_eof(mtd, offset)) {
            fprintf(stderr, "Skipped block at 0x%" PRIx64 " - bad\n", offset);
            offset += mtd_blocksize(mtd);
        }

        if (mtd_lseek(mtd, offset, SEEK_SET) < 0) {
            fprintf(stderr, "Unable to seek: %s\n", mtd_strerror(mtd));
            retval = -1;
            goto done;
        }

        len = file_read(&file, buffer, write_size);
        if (len < 0) {
            fprintf(stderr, "Failed to read from file: %s\n",
                    strerror(errno));
            retval = -1;
            goto done;
        }
        if (len == 0)
            continue;

        len = mtd_write(mtd, buffer, write_size);

        if (len < 0) {
            fprintf(stderr, "Write failure at 0x%x: %s\n",
                    file.pos - write_size, mtd_strerror(mtd));
            //         retval = -1;
            //         goto done;
        } else if (len != write_size) {
            fprintf(stderr,
                    "Write failure insufficient data written @0x%08" PRIx64
                    " (%d "
                    "!= %d)\n",
                    offset, len, write_size);
            retval = -1;
            goto done;
        }
        print_percentage(file.pos, file.size, 1);

        offset += write_size;
    }
    print_percentage(file.size, file.size, 1);

done:
    if (buffer)
        free(buffer);
    if (mtd)
        mtd_dispose(mtd);
    file_close(&file);
    return retval;
}

static int do_write_raw(char *device_name, char *filename, uint64_t offset)
{
    mtd_info *mtd = NULL;
    int retval = 0;
    char *buffer = NULL, *oob_buffer = NULL;
    int blocksize, oobsize, pagesize;
    file_info file = {0};

    mtd = mtd_new_auto(device_name, 0);
    if (!mtd) {
        retval = -1;
        goto done;
    }

    pagesize = mtd_pagesize(mtd);
    oobsize = mtd_oobsize(mtd);
    blocksize = mtd_blocksize(mtd);

    if (pagesize == 1) {
        fprintf(stderr, "Page size = 1 implies this is not a NAND device.\n"
                        "Don't use raw writing\n");
        goto done;
    }

    retval = file_new(&file, filename, "rb");
    if (retval < 0)
        goto done;

    if (file.size % (oobsize + pagesize)) {
        fprintf(stderr, "File size %d is not a multiple of %d\n", file.size,
                oobsize + pagesize);
        retval = -1;
        goto done;
    }

    buffer = malloc(pagesize);
    if (!buffer) {
        fprintf(stderr, "Unable to allocate buffer: %s\n", strerror(errno));
        retval = -1;
        goto done;
    }

    oob_buffer = malloc(oobsize);
    if (!oob_buffer) {
        fprintf(stderr, "Unable to allocate oob buffer: %s\n",
                strerror(errno));
        retval = -1;
        goto done;
    }

    while (!file_eof(&file)) {
        int len;

        while (bad_block_skipping && mtd_block_is_bad(mtd, offset) &&
               !mtd_eof(mtd, offset)) {
            fprintf(stderr, "Skipped block at 0x%" PRIx64 " - bad\n", offset);
            offset += blocksize;
        }

        if (mtd_lseek(mtd, offset, SEEK_SET) < 0) {
            fprintf(stderr, "Unable to seek: %s\n", mtd_strerror(mtd));
            retval = -1;
            goto done;
        }

        /* Read & write the page data */
        len = file_read(&file, buffer, pagesize);
        if (len == 0 && errno == 0 && file_eof(&file))
            break;
        if (len < 0 || len != pagesize) {
            fprintf(stderr, "Failed to read from file: %s\n",
                    strerror(errno));
            retval = -1;
            goto done;
        }

        len = mtd_page_write(mtd, offset, buffer);

        if (len < 0 || len != pagesize) {
            fprintf(stderr,
                    "Page write failure at NAND offset 0x%" PRIx64 ", "
                    "file offset 0x%x: %s (%d bytes written)\n",
                    offset, file.pos - pagesize, mtd_strerror(mtd), len);
            retval = -1;
            goto done;
        }

        /* Read & write the OOB data */
        len = file_read(&file, oob_buffer, oobsize);
        if (len < 0 || len != oobsize) {
            fprintf(stderr, "Failed to read from file: %s\n",
                    strerror(errno));
            retval = -1;
            goto done;
        }

        len = mtd_page_write_oob(mtd, offset, oob_buffer);

        if (len < 0) {
            fprintf(stderr,
                    "OOB write failure at 0x%x: %s (%d bytes written)\n",
                    file.pos - oobsize, mtd_strerror(mtd), len);
            retval = -1;
            goto done;
        }

        print_percentage(file.pos, file.size, 1);

        offset += pagesize;
    }
    print_percentage(file.size, file.size, 1);

done:
    if (buffer)
        free(buffer);
    if (mtd)
        mtd_dispose(mtd);
    file_close(&file);
    return retval;
}

static void do_hex_ascii(char *buf, const unsigned char *data, int len)
{
    int j, out = 0;
    char c;

    out += sprintf(buf + out, " ");
    for (j = 0; j < len; j++)
        if (data[j])
            out += sprintf(buf + out, "%02X ", data[j]);
        else
            out += sprintf(buf + out, "   ");

    out += sprintf(buf + out, " ");
    for (j = 0; j < len; j++) {
        c = data[(j)];
        if (!isascii(c) || !isprint(c))
            c = '.';
        out += sprintf(buf + out, "%c", c);
    }
}

/** show the user what the differences are between blocks */

static void verify_explain(unsigned char *good, unsigned char *bad, int size)
{
    char str[100];
    int upto, columns;
    int line = 0, i;

#define MAX_LINES 10 // maximum number of wrong lines to print

#define COLUMNS 80

    // display such that we can fit the two lots of data side by size
    // work out how many hex bytes can fit on a line
    // need 4 chars for address, 2 for spacing, 3 for each hex digit, 1 for
    // ascii
    columns = (COLUMNS - 4 - 2) / (4 + 1);

    // multiple of 8, but must be at least 1
    columns &= ~7;
    columns = max(columns, 1);

    printf("Addr  %*sBad xor (flash contents)\n", -columns * 5 + 5, "Good");

    // print data
    for (upto = 0; upto < size;
         upto += columns, bad += columns, good += columns) {
        // if data is the same, skip
        if (0 == memcmp(good, bad, columns))
            continue;

        if (line++ == 10)
            break;

        // print address
        printf("%04x:", upto);
        do_hex_ascii(str, good, columns);
        printf("%s ", str);
        for (i = 0; i < columns; i++)
            bad[i] ^= good[i];
        do_hex_ascii(str, bad, columns);
        printf("%s\n", str);
    }
}

static int do_read(char *device_name, char *filename, int length,
                   uint64_t offset, file_info *verify)
{
    mtd_info *mtd = NULL;
    FILE *fp = NULL;
    char *buffer = NULL;
    char *vbuffer = NULL;
    int retval = 0;
    uint64_t end = offset + length;
    uint64_t start = offset;
    int blocksize;

    mtd = mtd_new_auto(device_name, 1);
    if (!mtd) {
        retval = -1;
        goto done;
    }

    blocksize = mtd_blocksize(mtd);
    buffer = malloc(blocksize);
    if (verify)
        vbuffer = malloc(blocksize);
    if (!buffer || (verify && !vbuffer)) {
        fprintf(stderr, "Unable to allocate buffer: %s\n", strerror(errno));
        retval = -1;
        goto done;
    }

    if (filename && (fp = fopen(filename, "wb")) == NULL) {
        fprintf(stderr, "Failed to open file %s: %s\n", filename,
                strerror(errno));
        retval = -1;
        goto done;
    }

    while (offset < end && !mtd_eof(mtd, offset)) {
        if (bad_block_skipping && mtd_block_is_bad(mtd, offset) &&
            !mtd_eof(mtd, offset)) {
            fprintf(stderr,
                    "Skipped block at 0x%" PRIx64 " - bad (end: 0x%" PRIx64
                    ")\n",
                    offset, end);
            end += blocksize; // since we are now reading a bit more to get to
                              // 'length'
        } else {
            uint64_t write_size;

            if (mtd_lseek(mtd, offset, SEEK_SET) < 0) {
                fprintf(stderr, "Unable to seek: %s\n", mtd_strerror(mtd));
                retval = -1;
                goto done;
            }

            if (mtd_read(mtd, buffer, blocksize) < 0) {
                fprintf(stderr, "Read failure: %s\n", mtd_strerror(mtd));
                retval = -1;
                goto done;
            }

            write_size = min(
                blocksize,
                end -
                    offset); // don't write the full block if we don't want it

            if (fp && fwrite(buffer, write_size, 1, fp) != 1) {
                fprintf(stderr,
                        "Unable to write to output at offset: %" PRIx64
                        ": %s\n",
                        offset, strerror(errno));
                retval = -1;
                goto done;
            }

            // verify data if required
            if (verify) {
                retval = file_read(verify, vbuffer, write_size);
                if (retval < 0) {
                    fprintf(stderr, "File read failure at 0x%x\n",
                            verify->pos);
                    goto done;
                }
                if (0 != memcmp(buffer, vbuffer, write_size)) {
                    fprintf(stderr, "Verify failure at 0x%" PRIx64 "\n",
                            verify->pos - write_size);
                    verify_explain((unsigned char *)vbuffer,
                                   (unsigned char *)buffer, write_size);
                    retval = -1;
                    goto done;
                }
            }

            print_percentage(offset - start, end - start, 1);
        }
        offset += blocksize;
    }

    print_percentage(end - start, end - start, 1);
    retval = 0;

done:
    if (fp)
        fclose(fp);
    if (buffer)
        free(buffer);
    if (vbuffer)
        free(vbuffer);
    if (mtd)
        mtd_dispose(mtd);
    return retval;
}

static int do_read_raw(char *device_name, char *filename, int length,
                       int skip_empty)
{
    mtd_info *mtd = NULL;
    FILE *fp = NULL;
    char *page_buffer = NULL;
    char *oob_buffer = NULL;
    int retval = 0;
    uint64_t end;
    int blocksize, pagesize;
    uint64_t offset;

    mtd = mtd_new_auto(device_name, 1);
    if (!mtd) {
        retval = -1;
        goto done;
    }

    if (length == 0)
        end = mtd_size(mtd);
    else
        end = length;
    blocksize = mtd_blocksize(mtd);
    pagesize = mtd_pagesize(mtd);
    page_buffer = malloc(pagesize);
    if (!page_buffer) {
        fprintf(stderr, "Unable to allocate page buffer: %s\n",
                strerror(errno));
        retval = -ENOMEM;
        goto done;
    }
    oob_buffer = malloc(mtd_oobsize(mtd));
    if (!oob_buffer) {
        fprintf(stderr, "Unable to allocate oob buffer: %s\n",
                strerror(errno));
        retval = -ENOMEM;
        goto done;
    }

    if (filename && (fp = fopen(filename, "wb")) == NULL) {
        fprintf(stderr, "Failed to open file %s: %s\n", filename,
                strerror(errno));
        retval = -1;
        goto done;
    }

    offset = 0;
    while (!mtd_eof(mtd, offset) && offset < end) {
        if (bad_block_skipping && mtd_block_is_bad(mtd, offset) &&
            !mtd_eof(mtd, offset)) {
            fprintf(stderr,
                    "Skipped block at 0x%" PRIx64 " - bad (end: 0x%" PRIx64
                    ")\n",
                    offset, end);
            end += blocksize; // since we are now reading a bit more to get to
                              // 'length'
            offset = (offset + blocksize) & ~(blocksize - 1);
        } else {
            if (mtd_lseek(mtd, offset, SEEK_SET) < 0) {
                fprintf(stderr, "Unable to seek: %s\n", mtd_strerror(mtd));
                retval = -1;
                goto done;
            }

            if (mtd_read(mtd, page_buffer, pagesize) < 0) {
                fprintf(stderr, "Read failure: %s\n", mtd_strerror(mtd));
                retval = -1;
                goto done;
            }

            if (mtd_page_read_oob(mtd, offset, oob_buffer) < 0) {
                fprintf(stderr,
                        "Unable to read oob at offset: %" PRIx64 ": %s\n",
                        offset, mtd_strerror(mtd));
                retval = -1;
                goto done;
            }

            /* Skip any pages that are fully erased. This is useful for making
             * copies of YAFFS filesystems
             */
            if (skip_empty) {
                int i;
                for (i = 0; i < pagesize; i++)
                    if (page_buffer[i] != 0xff)
                        break;
                if (i == pagesize) {
                    for (i = 0; i < mtd_oobsize(mtd); i++)
                        if (oob_buffer[i] != 0xff)
                            break;
                    if (i == mtd_oobsize(mtd))
                        goto next;
                }
            }

            if (fp && fwrite(page_buffer, pagesize, 1, fp) != 1) {
                fprintf(stderr,
                        "Unable to write to output at offset: %" PRIx64
                        ": %s\n",
                        offset, strerror(errno));
                retval = -1;
                goto done;
            }

            if (fp && fwrite(oob_buffer, mtd_oobsize(mtd), 1, fp) != 1) {
                fprintf(stderr,
                        "Unable to write oob to output at offset: %" PRIx64
                        ": %s\n",
                        offset, strerror(errno));
                retval = -1;
                goto done;
            }

        next:
            print_percentage(offset, end, 1);
            offset += pagesize;
        }
    }

    print_percentage(end, end, 1);
    retval = 0;

done:
    if (fp)
        fclose(fp);
    if (page_buffer)
        free(page_buffer);
    if (oob_buffer)
        free(oob_buffer);
    if (mtd)
        mtd_dispose(mtd);
    return retval;
}

static int do_verify(char *device_name, char *filename, uint64_t offset)
{
    int retval = 0;
    file_info file;

    retval = file_new(&file, filename, "rb");
    if (retval < 0)
        return retval;

    retval = do_read(device_name, NULL, file.size, offset, &file);
    if (retval == 0)
        printf("File %s matches %s\n", filename, device_name);

    file_close(&file);

    return retval;
}

static char printable(char f)
{
    if (f < 0x20 || f >= 0x7f)
        return '.';
    return f;
}

static void dump_data(char *data, int size)
{
    int i;
#define LINELEN 16
    for (i = 0; i < size; i += LINELEN) {
        int remaining = min(LINELEN, size - i);
        int l;

        printf("%3.3x: ", i);
        for (l = 0; l < remaining; l++)
            printf("%2.2X ", data[i + l]);
        printf("%*s", (LINELEN - remaining) * 3, "");
        for (l = 0; l < remaining; l++)
            printf("%c", printable(data[i + l]));
        printf("\n");
    }
}

static int do_dump(char *device_name, uint64_t offset, int page_count)
{
    mtd_info *mtd = NULL;
    char *page_data = NULL;
    char *oob_data = NULL;
    int retval = 0;
    uint64_t end;

    mtd = mtd_new_auto(device_name, 1);
    if (!mtd) {
        fprintf(stderr, "Unable to open '%s'\n", device_name);
        return -1;
    }
    end = offset + page_count * mtd_pagesize(mtd);
    page_data = malloc(mtd_pagesize(mtd));
    if (mtd_oobsize(mtd))
        oob_data = malloc(mtd_oobsize(mtd));

    /* We want RAW reads here if possible */
    for (; offset < end; offset += mtd_pagesize(mtd)) {
        if (mtd_page_read(mtd, offset, page_data) != 0) {
            fprintf(stderr, "Unable to read page @%" PRIx64 "\n", offset);
            retval = -1;
            goto done;
        }
        printf("Page @%" PRIx64 "\n", offset);
        dump_data(page_data, mtd_pagesize(mtd));

        if (mtd_oobsize(mtd)) {
            if (mtd_page_read_oob(mtd, offset, oob_data) != 0) {
                fprintf(stderr, "Unable to read oob data @%" PRIx64 "\n",
                        offset);
                retval = -1;
                goto done;
            }
            printf("OOB @%" PRIx64 "\n", offset);
            dump_data(oob_data, mtd_oobsize(mtd));
        }
    }

done:
    if (mtd)
        mtd_dispose(mtd);
    if (page_data)
        free(page_data);
    if (oob_data)
        free(oob_data);

    return retval;
}

static int info(char *device_name, int bad_scan)
{
    mtd_info *mtd;
    unsigned blocksize = 0;
    uint64_t size, offset;
    unsigned bad_blocks = 0;
    unsigned total_blocks;
    char str[20];
    int i;

    mtd = mtd_new_auto(device_name, 1);
    if (!mtd) {
        fprintf(stderr, "Unable to open '%s'\n", device_name);
        return -1;
    }

    blocksize = mtd_blocksize(mtd);
    total_blocks = mtd_blockcount(mtd);
    size = mtd_size(mtd);

    printf("Partition name: '%s'\n", mtd_partition_name(mtd));
    printf("Filename: %s\n", mtd_filename(mtd));
    printf("MTD Type: %s\n", mtd_type_name(mtd));
    printf("Erase size: 0x%x (%d kB)\n", mtd_erasesize(mtd),
           mtd_erasesize(mtd) / 1024);
    printf("Region count: %d\n", mtd_region_count(mtd));
    for (i = 0; i < mtd_region_count(mtd); i++) {
        uint32_t offset, erasesize, numblocks;
        mtd_region_info(mtd, i, &offset, &erasesize, &numblocks);
        printf("Region %d: offset=0x%x erasesize=0x%x numblocks=%d\n", i,
               offset, erasesize, numblocks);
    }
    printf("Block size: 0x%x (%d kB)\n", blocksize, blocksize / 1024);
    printf("Block count: %d\n", total_blocks);
    printf("OOB size: %d\n", mtd_oobsize(mtd));
    printf("OOB Avail: %d\n", mtd_oobavail(mtd));
    printf("Page size: 0x%x (%d B)\n", mtd_pagesize(mtd), mtd_pagesize(mtd));
    printf("Pages/Block: %d\n", mtd_blocksize(mtd) / mtd_pagesize(mtd));
    util_bytes_to_user(str, size);
    printf("Size: 0x%" PRIx64 " (%s)\n", size, str);
    printf("Flags: %s\n", mtd_flags_name(mtd));
    printf("ECC mode: %s\n", mtd_eccmode_name(mtd));

    for (offset = 0; offset < size; offset += blocksize) {
        int ret;
        if (bad_scan)
            ret = mtd_block_is_bad_raw(mtd, offset);
        else
            ret = mtd_block_is_bad(mtd, offset);
        if (ret) {
            if (bad_blocks < 50)
                printf("Bad block @0x%" PRIx64 ": %d\n", offset, ret);
            else if (bad_blocks == 50)
                printf("...skipping remaining bad blocks display\n");
            bad_blocks++;
        }
    }

    printf("Bad blocks: %d (%3.3f%%)\n", bad_blocks,
           total_blocks ? (bad_blocks * 100.0) / total_blocks : 100);
    util_bytes_to_user(str, (total_blocks - bad_blocks) * blocksize);
    printf("Available blocks: %d (%s)\n", (total_blocks - bad_blocks), str);

    mtd_dispose(mtd);

    return 0;
}

static int do_mark_bad(char *device_name, uint64_t offset)
{
    mtd_info *mtd = NULL;

    mtd = mtd_new_auto(device_name, 0);
    if (!mtd) {
        fprintf(stderr, "Unable to open '%s'", device_name);
        return -1;
    }

    if (mtd_block_mark_bad_check(mtd, offset) < 0) {
        fprintf(stderr, "Unable to mark 0x%" PRIx64 " bad: %s", offset,
                mtd_strerror(mtd));
        mtd_dispose(mtd);
        return -1;
    }

    mtd_dispose(mtd);

    return 0;
}

#define STRESS_THREADS 4

/* Shared state between all stress threads */
typedef struct {
    pthread_mutex_t lock;
    uint32_t *block_seeds; /* per-block seed; 0 = erased */
    uint8_t *inuse;        /* non-zero while a thread is operating on block */
    unsigned int blocksize;
    unsigned int block_count;
    char *device_name;
    time_t end_time;
    /* Atomically-updated counters written by threads, read by main */
    atomic_uintmax_t iterations;
    atomic_uintmax_t read_bytes, write_bytes, erase_bytes;
    atomic_uintmax_t read_ms, write_ms, erase_ms;
    atomic_uintmax_t read_errors, write_errors, erase_errors;
} stress_shared;

/* Per-thread arguments */
typedef struct {
    stress_shared *shared;
    int thread_id;
} stress_thread_args;

/* Fill a buffer with deterministic pseudo-random data derived from a seed.
 * The same seed always produces the same pattern, allowing read-back
 * verification. A seed of 0 is reserved to mean "erased". */
static void fill_block_from_seed(char *buf, int size, uint32_t seed)
{
    uint32_t state = seed;
    int i;

    for (i = 0; i < size; i++) {
        state = state * 1664525u + 1013904223u; /* Knuth LCG */
        buf[i] = (char)((state >> 16) & 0xff);
    }
}

static void *stress_thread(void *arg)
{
    stress_thread_args *ta = arg;
    stress_shared *sh = ta->shared;
    unsigned int blocksize = sh->blocksize;
    mtd_info *mtd = NULL;
    char *block_buf = NULL;
    char *expected_buf = NULL;
    /* Per-thread rand state to avoid locking rand's global seed */
    unsigned int rand_state =
        (unsigned int)(time(NULL) ^
                       ((unsigned int)ta->thread_id * 2654435761u));

    mtd = mtd_new_auto(sh->device_name, 0);
    if (!mtd) {
        fprintf(stderr, "Thread %d: unable to open %s\n", ta->thread_id,
                sh->device_name);
        return NULL;
    }

    block_buf = malloc(blocksize);
    expected_buf = malloc(blocksize);
    if (!block_buf || !expected_buf) {
        fprintf(stderr, "Thread %d: unable to allocate buffers\n",
                ta->thread_id);
        goto done;
    }

    while (time(NULL) < sh->end_time) {
        uint32_t block_idx =
            (uint32_t)(rand_r(&rand_state) % sh->block_count);
        uint64_t block_offset = (uint64_t)block_idx * blocksize;
        uint32_t seed;
        unsigned int op_start;
        int do_write;

        if (mtd_block_is_bad(mtd, block_offset))
            continue;

        /* Claim the block; skip if another thread is already using it */
        pthread_mutex_lock(&sh->lock);
        if (sh->inuse[block_idx]) {
            pthread_mutex_unlock(&sh->lock);
            continue;
        }
        sh->inuse[block_idx] = 1;
        seed = sh->block_seeds[block_idx];
        do_write = rand_r(&rand_state) & 1;
        pthread_mutex_unlock(&sh->lock);

        if (do_write) {
            /* WRITE: erase block, then write with a fresh seed */
            uint32_t new_seed;

            op_start = get_msec();
            if (mtd_blocks_erase(mtd, block_offset, 1) < 0) {
                fprintf(stderr, "Erase error at block 0x%" PRIx64 ": %s\n",
                        block_offset, mtd_strerror(mtd));
                atomic_fetch_add(&sh->erase_errors, 1);
                pthread_mutex_lock(&sh->lock);
                sh->inuse[block_idx] = 0;
                pthread_mutex_unlock(&sh->lock);
                continue;
            }
            atomic_fetch_add(&sh->erase_ms, get_msec() - op_start);
            atomic_fetch_add(&sh->erase_bytes, blocksize);

            do {
                new_seed = (uint32_t)rand_r(&rand_state);
            } while (new_seed == 0);
            fill_block_from_seed(block_buf, blocksize, new_seed);

            mtd_lseek(mtd, block_offset, SEEK_SET);
            op_start = get_msec();
            if (mtd_write(mtd, block_buf, blocksize) != (int)blocksize) {
                fprintf(stderr, "Write error at block 0x%" PRIx64 ": %s\n",
                        block_offset, mtd_strerror(mtd));
                atomic_fetch_add(&sh->write_errors, 1);
                /* Leave seed as 0 (erased) after a failed write */
                pthread_mutex_lock(&sh->lock);
                sh->block_seeds[block_idx] = 0;
                sh->inuse[block_idx] = 0;
                pthread_mutex_unlock(&sh->lock);
                continue;
            }
            atomic_fetch_add(&sh->write_ms, get_msec() - op_start);
            atomic_fetch_add(&sh->write_bytes, blocksize);

            pthread_mutex_lock(&sh->lock);
            sh->block_seeds[block_idx] = new_seed;
            sh->inuse[block_idx] = 0;
            pthread_mutex_unlock(&sh->lock);

        } else {
            /* READ: read back and verify against expected pattern */
            if (seed == 0)
                memset(expected_buf, 0xff, blocksize);
            else
                fill_block_from_seed(expected_buf, blocksize, seed);

            mtd_lseek(mtd, block_offset, SEEK_SET);
            op_start = get_msec();
            if (mtd_read(mtd, block_buf, blocksize) < 0) {
                fprintf(stderr, "Read error at block 0x%" PRIx64 ": %s\n",
                        block_offset, mtd_strerror(mtd));
                atomic_fetch_add(&sh->read_errors, 1);
                pthread_mutex_lock(&sh->lock);
                sh->inuse[block_idx] = 0;
                pthread_mutex_unlock(&sh->lock);
                continue;
            }
            atomic_fetch_add(&sh->read_ms, get_msec() - op_start);
            atomic_fetch_add(&sh->read_bytes, blocksize);

            if (memcmp(block_buf, expected_buf, blocksize) != 0) {
                fprintf(stderr,
                        "Data mismatch at block 0x%" PRIx64
                        " (seed 0x%08" PRIx32 ")\n",
                        block_offset, seed);
                atomic_fetch_add(&sh->read_errors, 1);
            }

            pthread_mutex_lock(&sh->lock);
            sh->inuse[block_idx] = 0;
            pthread_mutex_unlock(&sh->lock);
        }

        atomic_fetch_add(&sh->iterations, 1);
    }

done:
    free(block_buf);
    free(expected_buf);
    if (mtd)
        mtd_dispose(mtd);
    return NULL;
}

static int do_stress(char *device_name, int seconds)
{
    mtd_info *mtd = NULL;
    stress_shared shared;
    stress_thread_args thread_args[STRESS_THREADS];
    pthread_t threads[STRESS_THREADS];
    int threads_started = 0;
    int retval = 0;
    int i;
    unsigned int start_ms, elapsed_ms;
    unsigned int last_print_ms;

    memset(&shared, 0, sizeof(shared));
    memset(thread_args, 0, sizeof(thread_args));
    atomic_init(&shared.iterations, 0);
    atomic_init(&shared.read_bytes, 0);
    atomic_init(&shared.write_bytes, 0);
    atomic_init(&shared.erase_bytes, 0);
    atomic_init(&shared.read_ms, 0);
    atomic_init(&shared.write_ms, 0);
    atomic_init(&shared.erase_ms, 0);
    atomic_init(&shared.read_errors, 0);
    atomic_init(&shared.write_errors, 0);
    atomic_init(&shared.erase_errors, 0);

    mtd = mtd_new_auto(device_name, 0);
    if (!mtd)
        return -1;

    shared.blocksize = mtd_blocksize(mtd);
    shared.block_count = mtd_blockcount(mtd);
    shared.device_name = device_name;

    shared.block_seeds = calloc(shared.block_count, sizeof(uint32_t));
    shared.inuse = calloc(shared.block_count, sizeof(uint8_t));
    if (!shared.block_seeds || !shared.inuse) {
        fprintf(stderr, "Unable to allocate memory: %s\n", strerror(errno));
        retval = -1;
        goto done;
    }
    pthread_mutex_init(&shared.lock, NULL);

    printf("Erasing entire partition %s...\n", device_name);
    if (erase_mtd(mtd, 0, mtd_size(mtd), 0) < 0) {
        fprintf(stderr, "Failed to erase partition\n");
        retval = -1;
        goto done;
    }
    /* block_seeds already all-zero from calloc, matching erased state */

    /* Close the mtd handle before threads open their own */
    mtd_dispose(mtd);
    mtd = NULL;

    shared.end_time = time(NULL) + seconds;
    start_ms = get_msec();
    printf("Starting stress test for %d seconds on %s "
           "(%u blocks of %u bytes each) with %d threads...\n",
           seconds, device_name, shared.block_count, shared.blocksize,
           STRESS_THREADS);

    for (i = 0; i < STRESS_THREADS; i++) {
        thread_args[i].shared = &shared;
        thread_args[i].thread_id = i;
        if (pthread_create(&threads[i], NULL, stress_thread,
                           &thread_args[i]) != 0) {
            fprintf(stderr, "Failed to create thread %d: %s\n", i,
                    strerror(errno));
            shared.end_time = time(NULL); /* tell running threads to stop */
            break;
        }
        threads_started++;
    }

    /* Print progress every 10 s while threads are running */
    last_print_ms = 0;
    while (time(NULL) < shared.end_time) {
        sleep(1);
        if (get_msec() - start_ms < last_print_ms + 10000)
            continue;
        last_print_ms = get_msec() - start_ms;

        {
            uintmax_t iters = atomic_load(&shared.iterations);
            uintmax_t wb = atomic_load(&shared.write_bytes);
            uintmax_t wms = atomic_load(&shared.write_ms);
            uintmax_t rb = atomic_load(&shared.read_bytes);
            uintmax_t rms = atomic_load(&shared.read_ms);
            uintmax_t eb = atomic_load(&shared.erase_bytes);
            uintmax_t ems = atomic_load(&shared.erase_ms);
            uintmax_t we = atomic_load(&shared.write_errors);
            uintmax_t re = atomic_load(&shared.read_errors);
            uintmax_t ee = atomic_load(&shared.erase_errors);
            char ws[20], wrs[20], rs[20], rrs[20], es[20], ers[20];
            util_bytes_to_user(ws, wb);
            util_bytes_to_userf(wrs, wms ? (double)(wb * 1000) / wms : 0);
            util_bytes_to_user(rs, rb);
            util_bytes_to_userf(rrs, rms ? (double)(rb * 1000) / rms : 0);
            util_bytes_to_user(es, eb);
            util_bytes_to_userf(ers, ems ? (double)(eb * 1000) / ems : 0);
            printf("\r%ds remaining, %" PRIuMAX " iters, "
                   "W:%s@%s/s R:%s@%s/s E:%s@%s/s "
                   "errs W:%" PRIuMAX " R:%" PRIuMAX " E:%" PRIuMAX "   ",
                   (int)(shared.end_time - time(NULL)), iters, ws, wrs, rs,
                   rrs, es, ers, we, re, ee);
        }
        fflush(stdout);
    }

    for (i = 0; i < threads_started; i++)
        pthread_join(threads[i], NULL);

    elapsed_ms = get_msec() - start_ms;
    {
        uintmax_t iters = atomic_load(&shared.iterations);
        uintmax_t wb = atomic_load(&shared.write_bytes);
        uintmax_t wms = atomic_load(&shared.write_ms);
        uintmax_t rb = atomic_load(&shared.read_bytes);
        uintmax_t rms = atomic_load(&shared.read_ms);
        uintmax_t eb = atomic_load(&shared.erase_bytes);
        uintmax_t ems = atomic_load(&shared.erase_ms);
        uintmax_t we = atomic_load(&shared.write_errors);
        uintmax_t re = atomic_load(&shared.read_errors);
        uintmax_t ee = atomic_load(&shared.erase_errors);
        char ws[20], wrs[20], rs[20], rrs[20], es[20], ers[20];

        util_bytes_to_user(ws, wb);
        util_bytes_to_userf(wrs, wms ? (double)(wb * 1000) / wms : 0);
        util_bytes_to_user(rs, rb);
        util_bytes_to_userf(rrs, rms ? (double)(rb * 1000) / rms : 0);
        util_bytes_to_user(es, eb);
        util_bytes_to_userf(ers, ems ? (double)(eb * 1000) / ems : 0);

        printf("\nStress test complete: %" PRIuMAX " iterations in %u ms\n",
               iters, elapsed_ms);
        printf("  Written: %s @ %s/s\n", ws, wrs);
        printf("  Read:    %s @ %s/s\n", rs, rrs);
        printf("  Erased:  %s @ %s/s\n", es, ers);
        printf("  Write errors: %" PRIuMAX "\n", we);
        printf("  Read errors:  %" PRIuMAX "\n", re);
        printf("  Erase errors: %" PRIuMAX "\n", ee);
        retval = (re || we || ee) ? -1 : 0;
    }

done:
    pthread_mutex_destroy(&shared.lock);
    free(shared.block_seeds);
    free(shared.inuse);
    if (mtd)
        mtd_dispose(mtd);
    return retval;
}

int main(int argc, char *argv[])
{
    int cmd = CMD_UNKNOWN;
    int i = 1;
    int retval = 0;
    uint64_t offset = 0;
    uint64_t length = -1;
    char *device = NULL;
    char *filename = NULL;
    int force = 0;

    while (i < argc) {
        if (strcmp(argv[i], "--ignore_bad") == 0) {
            bad_block_skipping = 0;
        } else if (strcmp(argv[i], "--info") == 0 && i + 1 < argc) {
            cmd = CMD_INFO;
            device = argv[i + 1];
            i += 1;
        } else if (strcmp(argv[i], "--info_scan") == 0 && i + 1 < argc) {
            cmd = CMD_INFO_SCAN;
            device = argv[i + 1];
            i += 1;
        } else if (strcmp(argv[i], "--erase") == 0 && i + 3 < argc) {
            cmd = CMD_ERASE;
            device = argv[i + 1];
            offset = strtoull(argv[i + 2], NULL, 0);
            length = strtoull(argv[i + 3], NULL, 0);
            i += 3;
        } else if (strcmp(argv[i], "--force_erase") == 0 && i + 3 < argc) {
            cmd = CMD_ERASE;
            device = argv[i + 1];
            offset = strtoull(argv[i + 2], NULL, 0);
            length = strtoull(argv[i + 3], NULL, 0);
            force = 1;
            i += 3;
        } else if (strcmp(argv[i], "--eraseall") == 0 && i + 1 < argc) {
            cmd = CMD_ERASEALL;
            device = argv[i + 1];
            i += 1;
        } else if (strcmp(argv[i], "--force_eraseall") == 0 && i + 1 < argc) {
            cmd = CMD_ERASEALL;
            device = argv[i + 1];
            force = 1;
            i += 1;
        } else if (strcmp(argv[i], "--quick_erase") == 0 && i + 1 < argc) {
            cmd = CMD_QUICK_ERASE;
            device = argv[i + 1];
            i += 1;
        } else if (strcmp(argv[i], "--write") == 0 && i + 2 < argc) {
            cmd = CMD_WRITE;
            device = argv[i + 1];
            filename = argv[i + 2];
            if (i + 3 < argc) {
                offset = strtoull(argv[i + 3], NULL, 0);
                i++;
            } else
                offset = 0;
            i += 2;
        } else if (strcmp(argv[i], "--write_raw") == 0 && i + 2 < argc) {
            cmd = CMD_WRITE_RAW;
            device = argv[i + 1];
            filename = argv[i + 2];
            if (i + 3 < argc) {
                offset = strtoull(argv[i + 3], NULL, 0);
                i++;
            } else
                offset = 0;
            i += 2;
        } else if (strcmp(argv[i], "--read") == 0 && i + 3 < argc) {
            cmd = CMD_READ;
            device = argv[i + 1];
            filename = argv[i + 2];
            length = strtoull(argv[i + 3], NULL, 0);
            if (i + 4 < argc) {
                offset = strtoull(argv[i + 4], NULL, 0);
                i++;
            } else
                offset = 0;
            i += 3;
        } else if (strcmp(argv[i], "--read_raw") == 0 && i + 2 < argc) {
            cmd = CMD_READ_RAW;
            device = argv[i + 1];
            filename = argv[i + 2];
            if (i + 3 < argc) {
                length = strtoull(argv[i + 3], NULL, 0);
                i++;
            } else
                length = 0;
            i += 2;
        } else if (strcmp(argv[i], "--read_raw_skip") == 0 && i + 2 < argc) {
            cmd = CMD_READ_RAW_SKIP;
            device = argv[i + 1];
            filename = argv[i + 2];
            if (i + 3 < argc) {
                length = strtoull(argv[i + 3], NULL, 0);
                i++;
            } else
                length = 0;
            i += 2;
        } else if (strcmp(argv[i], "--verify") == 0 && i + 2 < argc) {
            cmd = CMD_VERIFY;
            device = argv[i + 1];
            filename = argv[i + 2];
            if (i + 3 < argc) {
                offset = strtoull(argv[i + 3], NULL, 0);
                i++;
            } else
                offset = 0;
            i += 3;
        } else if (strcmp(argv[i], "--dump") == 0 && i + 2 < argc) {
            cmd = CMD_DUMP;
            device = argv[i + 1];
            offset = strtoull(argv[i + 2], NULL, 0);
            if (i + 3 < argc) {
                length = strtoull(argv[i + 3], NULL, 0);
                i++;
            } else
                length = 1;
            i += 3;
        } else if (strcmp(argv[i], "--markbad") == 0 && i + 2 < argc) {
            cmd = CMD_MARK_BAD;
            device = argv[i + 1];
            offset = strtoull(argv[i + 2], NULL, 0);
            i += 2;

        } else if (strcmp(argv[i], "--unlock") == 0 && i + 1 < argc) {
            cmd = CMD_UNLOCK;
            device = argv[i + 1];
            if (i + 3 < argc) {
                offset = strtoull(argv[i + 2], NULL, 0);
                length = strtoull(argv[i + 3], NULL, 0);
                i += 2;
            } else {
                offset = -1;
                length = -1;
            }
            i++;
        } else if (strcmp(argv[i], "--lock") == 0 && i + 3 < argc) {
            cmd = CMD_LOCK;
            device = argv[i + 1];
            offset = strtoull(argv[i + 2], NULL, 0);
            length = strtoull(argv[i + 3], NULL, 0);
            i += 3;
        } else if (strcmp(argv[i], "--rewrite") == 0 && i + 2 < argc) {
            cmd = CMD_REWRITE;
            device = argv[i + 1];
            filename = argv[i + 2];
            if (i + 3 < argc) {
                offset = strtoull(argv[i + 3], NULL, 0);
                i++;
            } else
                offset = 0;
            i += 2;
        } else if (strcmp(argv[i], "--stress") == 0 && i + 2 < argc) {
            cmd = CMD_STRESS;
            device = argv[i + 1];
            length = strtoull(argv[i + 2], NULL, 0);
            i += 2;
        }

        i++;
    }

    if (cmd == CMD_UNKNOWN) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    switch (cmd) {
    case CMD_INFO_SCAN:
        retval = info(device, 1);
        break;

    case CMD_INFO:
        retval = info(device, 0);
        break;

    case CMD_ERASE:
        retval = do_erase(device, offset, length, force);
        break;

    case CMD_QUICK_ERASE:
        retval = do_quick_erase(device);
        break;

    case CMD_ERASEALL:
        retval = do_erase(device, 0, -1, force);
        break;

    case CMD_WRITE:
        retval = do_write(device, filename, offset);
        break;

    case CMD_WRITE_RAW:
        retval = do_write_raw(device, filename, offset);
        break;

    case CMD_READ:
        retval = do_read(device, filename, length, offset, NULL);
        break;

    case CMD_READ_RAW:
        retval = do_read_raw(device, filename, length, 0);
        break;

    case CMD_READ_RAW_SKIP:
        retval = do_read_raw(device, filename, length, 1);
        break;

    case CMD_VERIFY:
        retval = do_verify(device, filename, offset);
        break;

    case CMD_DUMP:
        retval = do_dump(device, offset, length);
        break;

    case CMD_MARK_BAD:
        retval = do_mark_bad(device, offset);
        break;

    case CMD_UNLOCK:
        retval = do_unlock(device, offset, length);
        break;

    case CMD_LOCK:
        retval = do_lock(device, offset, length);
        break;

    case CMD_REWRITE:
        printf("Erasing %s\n", device);
        retval = do_erase(device, 0, -1, 0);
        if (retval == 0) {
            printf("Writing %s\n", filename);
            retval = do_write(device, filename, offset);
        }
        if (retval == 0) {
            printf("Verifying %s\n", filename);
            retval = do_verify(device, filename, offset);
        }
        break;

    case CMD_STRESS:
        retval = do_stress(device, (int)length);
        break;

    default:
        fprintf(stderr, "Don't handle %d yet", cmd);
        retval = -1;
        break;
    }

    if (retval != 0)
        fprintf(stderr, "FAILURE\n");

    return retval;
}
