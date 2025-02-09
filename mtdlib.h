/* ======================================================================
 *
 * File    : mtdlib.h
 * Project : Snapper
 * Author  : Andre Renaud/Simon Glass
 * Company : Bluewater Systems Ltd
 *           http://www.bluewatersys.com
 *
 * Provides an access library for mtd devices
 *
 * Licensed under GPLv2
 *
 * ======================================================================
 */

#ifndef __mtdlib_h
#define __mtdlib_h

#include <stdint.h>
#include <sys/types.h>

typedef void (*progress_callback)(const char *operation, uint64_t pos,
                                  uint64_t total);

typedef struct mtd_info mtd_info;
#define MTD_CALL(mtd, a)                                                     \
    ({                                                                       \
        int x = a;                                                           \
        if (x < 0) {                                                         \
            fprintf(stderr, "mtd error: %s\n", mtd_strerror(mtd));           \
            return -1;                                                       \
        }                                                                    \
        x;                                                                   \
    })

/* High level functions */

/**
 * Write a file to an mtd partition. The partition is fully erased and then
 * the file is written to it. Bad blocks are automatically skipped. If
 * verification is enabled then blocks will be read back to ensure that they
 * match the data that was written.
 *
 * @param file Name of file to write
 * @param mtd_partition Name of MTD partition to write to
 * @param max_verify_failures Maximum number of times to write to a block
 *                            before marking it as bad. If set to zero then
 *                            no verification of writes will be done
 * @param progress Optional callback to monitor progress
 * @return 0 on success or a negative errno code on error
 */
extern int mtd_write_file(const char *file, const char *mtd_partition,
                          int max_verify_failures,
                          progress_callback progress);

/**
 * Write a raw file to an mtd partition. The partition is fully erased and
 * then the file is written to it, including OOB data for each page. Bad
 * blocks are automatically skipped. The input file should be a multiple of
 * (page_size + oob_size)
 *
 * @param file Name of file to write
 * @param mtd_partition Name of MTD partition to write to
 * @param progress Optional callback to monitor progress
 * @return 0 on success or a negative errno code on error
 */
extern int mtd_write_file_raw(const char *file, const char *mtd_partition,
                              progress_callback progress);
/**
 * Erase an entire mtd partition
 *
 * @param mtd_part Name of the mtd parttition to erase
 * @param progress Optional callback to monitor progress
 * @return 0 on success or a negative errno code on error
 */
extern int mtd_erase_partition(const char *mtd_part,
                               progress_callback progress);

/*************************** error handling ***********************/
int mtd_get_error(mtd_info *mtd, char **message);
char *mtd_strerror(mtd_info *mtd);
void mtd_clear_error(mtd_info *mtd);
int mtd_set_error(mtd_info *mtd, char *op, int err, char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

int mtd_perr(mtd_info *mtd);

/*************************** settings & info **************************/
int mtd_region_count(mtd_info *mtd);
int mtd_region_info(mtd_info *mtd, uint32_t region, uint32_t *offset,
                    uint32_t *erasesize, uint32_t *numblocks);
int mtd_type(mtd_info *mtd);
char *mtd_type_name(mtd_info *mtd);
uint64_t mtd_size(mtd_info *mtd);
unsigned mtd_erasesize(mtd_info *mtd);
int mtd_flags(mtd_info *mtd);
char *mtd_flags_name(mtd_info *mtd);
char *mtd_sizestr(char *str, uint64_t x);
unsigned mtd_blocksize(mtd_info *mtd);
unsigned mtd_blockcount(mtd_info *mtd);
unsigned mtd_pagesize(mtd_info *mtd);
int mtd_ecctype(mtd_info *mtd);
int mtd_oobsize(mtd_info *mtd);
int mtd_oobavail(mtd_info *mtd);
int mtd_save_oobsel(mtd_info *mtd);
int mtd_restore_oobsel(mtd_info *mtd);
int mtd_eccmode(mtd_info *mtd);
char *mtd_eccmode_name(mtd_info *mtd);
char *mtd_filename(mtd_info *mtd);
char *mtd_partition_name(mtd_info *mtd);

/*************************** bad blocks ***************************/

int mtd_bad_block_count(mtd_info *mtd);
int mtd_block_is_bad(mtd_info *mtd, uint64_t offs);
int mtd_block_mark_bad(mtd_info *mtd, uint64_t offs);
int mtd_block_mark_bad_check(mtd_info *mtd, uint64_t offs);
int mtd_block_find_next_good(mtd_info *mtd, uint64_t *pos);
int mtd_block_write_next_good(mtd_info *mtd, uint64_t *offs, char *buffer);
int mtd_block_read_next_good(mtd_info *mtd, uint64_t *offs, char *buff);
int mtd_block_is_bad_raw(mtd_info *mtd, uint64_t pos);
int mtd_block_is_free(mtd_info *mtd, uint64_t pos);
int mtd_block_find_next_free(mtd_info *mtd, uint64_t *pos);

/************************ erase, read & write ************************/

int mtd_erase_bytes(mtd_info *mtd, uint64_t start, uint64_t nbytes);
int mtd_blocks_erase(mtd_info *mtd, uint64_t start, int nblocks);
int mtd_blocks_erase_nobad(mtd_info *mtd, uint64_t start, int nblocks);
uint64_t mtd_lseek(mtd_info *mtd, uint64_t start, int whence);
int mtd_read(mtd_info *mtd, char *buff, int size);
int mtd_write(mtd_info *mtd, const char *buff, int size);
int mtd_page_write(mtd_info *mtd, uint64_t start, const char *data);
int mtd_page_read(mtd_info *mtd, uint64_t start, char *data);
int mtd_block_write(mtd_info *mtd, uint64_t start, const char *data);
int mtd_block_read(mtd_info *mtd, uint64_t start, char *data);
int mtd_page_write_oob(mtd_info *mtd, uint64_t pos, const char *oob);
int mtd_page_read_oob(mtd_info *mtd, uint64_t pos, char *oob);

/************************** iterating and position *******************/

int mtd_start(mtd_info *mtd, uint64_t *pos);
int mtd_block_next(mtd_info *mtd, uint64_t *pos);
int mtd_eof(mtd_info *mtd, uint64_t pos);
int mtd_block_start(mtd_info *mtd, uint64_t block, uint64_t *pos);
int mtd_page_next(mtd_info *mtd, uint64_t *pos);
int mtd_blocknum(mtd_info *mtd, uint64_t pos);
int mtd_pagenum(mtd_info *mtd, uint64_t pos);

/************************ Locking and unlocking ***********************/
int mtd_unlock_blocks(mtd_info *mtd, uint64_t start, int nblocks);
int mtd_lock_blocks(mtd_info *mtd, uint64_t start, int nblocks);
int mtd_unlock(mtd_info *mtd, int start, int nbytes);
int mtd_lock(mtd_info *mtd, uint64_t start, int nbytes);

/********************** creating, opening and closing *****************/

int mtd_open(mtd_info *mtd, int readonly);

mtd_info *mtd_new_auto(const char *name, int readonly);
mtd_info *mtd_new_filename(const char *fname, int readonly);
mtd_info *mtd_new_chardev(int mtd_num, int readonly);
int mtd_close(mtd_info *mtd);
int mtd_dispose(mtd_info *mtd);

int mtd_find_part_name(const char *part_name);

// call this first. returns the library version number
int mtd_init(void);

#endif
