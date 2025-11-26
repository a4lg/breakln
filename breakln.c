/*

    breakln : Efficient hard link breaking utility

    breakln.c
    Main application

    Copyright (C) 2025 Tsukasa OI.

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom
    the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
    IN THE SOFTWARE.

*/

#include "config.h"

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/fs.h>

// Implementation Utilities
#include "breakln_impl/cmdline.h"
#include "breakln_impl/pathbuf_dyn.h"
#include "breakln_impl/signal_handler.h"

#define BREAKLN_EXIT_OK 0
#define BREAKLN_EXIT_FAIL_SAFE 1
#define BREAKLN_EXIT_FAIL_UNSAFE 2

// Minimum file system disruption mode: Attempts to relink the file path.
#define BREAKLN_RELINK_ATTEMPTS 10

// Dynamic path buffer for dirname
static struct dyn_pathbuf storage_name1;
// Dynamic path buffer for basename
static struct dyn_pathbuf storage_name2;

// Currently processing: path name
static char* pathname = NULL;
// Currently processing: directory name
static char* filedir = NULL;
// Currently processing: file name
static char* filename = NULL;
// Currently processing: directory handle
static int fd_dir = -1;
// Currently processing: input file handle
static int fd_in = -1;
// Currently processing: file stat
static struct stat stat_in;
// Currently processing: file inode number
static uintmax_t fino;

// Process a file: using minimum file system disruption mode.
static int process_file_min_tmpfile(void)
{
    int ret = BREAKLN_EXIT_FAIL_SAFE;

    // Create "temporary" file (going to be the output later).
    int fd_out = openat(fd_dir, ".", O_WRONLY | O_TMPFILE, (mode_t)0600);
    if (fd_out < 0) {
        fprintf(
            stderr, "%s: Failed to create destination without hard links (%s).\n",
            pathname, strerror(errno));
        goto out0;
    }

    // Check if the original file is empty.
    if (stat_in.st_size == 0) {
        // Empty file and subsequent cloning operations not needed.
        goto do_replace;
    }

#ifdef FICLONE
    // Clone the file as possible.
    if (ioctl(fd_out, FICLONE, fd_in) >= 0) {
        // FICLONE succeeded!
        ret = BREAKLN_EXIT_OK;
        goto do_replace;
    }
#endif

    // FICLONE is either not supported or failed.
    // Use copy_file_range instead.

    // Get maximum chunk size.
    size_t max_chunk_size = SIZE_MAX;
    {
        // Align to the page size if possible.
        long val = sysconf(_SC_PAGESIZE);
        if (val > 0 && val <= SIZE_MAX) {
            size_t pagesize = (size_t)val;
            max_chunk_size = max_chunk_size / pagesize * pagesize;
        }
    }

    // Interrupt
    if (breakln_interrupted) {
        fprintf(stderr, "%s: Interrupted while processing.\n", pathname);
        goto out1;
    }

    // Truncate (for partial failure of FICLONE).
    if (lseek(fd_out, 0, SEEK_SET) == -1 || ftruncate(fd_out, 0) < 0) {
        fprintf(
            stderr, "%s: Failed to prepare regular file copy (%s).\n",
            pathname, strerror(errno));
        goto out1;
    }

    // Copy file ranges.
    off_t filesize = stat_in.st_size;
    ssize_t chunk;
    do {
        // Interrupt
        if (breakln_interrupted) {
            fprintf(stderr, "%s: Interrupted while processing.\n", pathname);
            goto out1;
        }

        /*
            Portability Note:
            Even on the worst case, comparison between different integer
            types are safe as long as the both operands are non-negative.
        */
        size_t sz = filesize >= max_chunk_size
            ? max_chunk_size
            : (size_t)filesize;
        chunk = copy_file_range(fd_in, NULL, fd_out, NULL, sz, 0);
        if (chunk < 0) {
            fprintf(
                stderr, "%s: Failed to copy from the original file (%s).\n",
                pathname, strerror(errno));
            goto out1;
        }
        filesize -= (off_t)chunk;
    } while (filesize > 0 && chunk > 0);

    // Remove then replace if possible.
do_replace:
    ret = BREAKLN_EXIT_OK;
    for (int i = 0; i < BREAKLN_RELINK_ATTEMPTS; i++) {
        // Remove the original file (path).
        if (unlinkat(fd_dir, filename, 0) < 0 && errno != ENOENT) {
            fprintf(
                stderr, "%s: Failed to \"remove\" the original file (%s).\n",
                pathname, strerror(errno));
            ret = BREAKLN_EXIT_FAIL_SAFE;
            break;
        }

        // Relink to the original path (go to finalization on success).
        if (linkat(fd_out, "", fd_dir, filename, AT_EMPTY_PATH) == 0)
            goto out1;

        // Do not retry if an existing entry does not exist.
        if (errno != EEXIST) {
            fprintf(
                stderr, "%s (ino=%" PRIuMAX "): Failed to create destination without hard links (%s).\n",
                pathname, fino, strerror(errno));
            ret = BREAKLN_EXIT_FAIL_UNSAFE;
            break;
        }

        // Retry if an existing entry does exist,
        // expecting that the file is removed soon.
    }

    // If ret is a success, that means it failed to relink
    // (despite seveal attempts) and errno is EEXIST.
    if (ret == BREAKLN_EXIT_OK) {
        fprintf(
            stderr, "%s (ino=%" PRIuMAX "): Failed to create destination without hard links (%s).\n",
            pathname, fino, strerror(EEXIST));
        ret = BREAKLN_EXIT_FAIL_UNSAFE;
    }

    // Finalization
out1:
    if (ret == BREAKLN_EXIT_OK) {
        // Finalization: chmod to the original mode
        if (fchmod(fd_out, stat_in.st_mode & ~(mode_t)S_IFMT) < 0) {
            fprintf(
                stderr, "%s: Break link complete but failed to restore permission flags (%s).\n",
                pathname, strerror(errno));
            ret = BREAKLN_EXIT_FAIL_SAFE;
        }

        // Finalization: chown to the original owner (can fail)
        if (fchown(fd_out, stat_in.st_uid, stat_in.st_gid) < 0) {
            fprintf(
                stderr, "%s: (warning) Break link complete but failed to change its owner (%s).\n",
                pathname, strerror(errno));
            // Don't set error here.
        }
    }
    close(fd_out);
out0:
    return ret;
}

// Process a file.
static int process_file(char* pathname_inout)
{
    int ret = BREAKLN_EXIT_FAIL_SAFE;

    // Preprocess paths
    pathname = pathname_inout;
    size_t pathlen = strlen(pathname);
    if (pathlen > 0 && pathname[pathlen - 1] == '/') {
        // Trailing slash meaning a directory
        // (and handling with basename will not work correctly).
        fprintf(stderr, "%s: File name cannot end with trailing slash.\n", pathname);
        goto out0;
    }
    char* name1_base = dyn_pathbuf_strdup(&storage_name1, pathname, pathlen);
    char* name2_base = dyn_pathbuf_strdup(&storage_name2, pathname, pathlen);
    if (!name1_base || !name2_base) {
        fprintf(stderr, "%s: Failed to allocate memory to process paths.\n", cmdname);
        goto out0;
    }
    filedir = dirname(name1_base);
    filename = basename(name2_base);

    // Open the directory.
    fd_dir = open(filedir, O_RDONLY | O_DIRECTORY);
    if (fd_dir < 0) {
        fprintf(
            stderr, "%s: Cannot open directory (%s).\n",
            filedir, strerror(errno));
        goto out0;
    }

    // Check if the file is opened and the metadata can be read.
    fd_in = openat(fd_dir, filename, O_RDONLY | O_NOFOLLOW);
    if (fd_in < 0) {
        fprintf(
            stderr, "%s: %s.\n", pathname,
            errno == ELOOP
                ? "Symbolic link is not supported"
                : strerror(errno));
        goto out1;
    }
    if (fstat(fd_in, &stat_in) < 0) {
        fprintf(
            stderr, "%s: %s.\n", pathname,
            strerror(errno));
        goto out2;
    }
    fino = (uintmax_t)stat_in.st_ino;

    // Only regular files are supported.
    if (!S_ISREG(stat_in.st_mode)) {
        fprintf(stderr, "%s: Only regular files are supported.\n", pathname);
        goto out2;
    }

    // Skip if there's no need to break hard links.
    if (stat_in.st_nlink <= 1) {
        ret = BREAKLN_EXIT_OK;
        goto out2;
    }

    breakln_interrupt_enter();
    ret = process_file_min_tmpfile();
    breakln_interrupt_leave();
out2:
    close(fd_in);
out1:
    close(fd_dir);
out0:
    return ret;
}

int main(int argc, char** argv)
{
    parse_cmdline(argc, argv);
    dyn_pathbuf_init(&storage_name1);
    dyn_pathbuf_init(&storage_name2);
    int ret = BREAKLN_EXIT_OK;
    for (int i = 0; i < files_count; i++) {
        ret = process_file(files[i]);
        if (ret != BREAKLN_EXIT_OK)
            break;
        if (breakln_interrupted) {
            if (i + 1 != files_count) {
                fprintf(stderr, "%s: Interrupted before handling this.\n", files[i + 1]);
                ret = 0x80 + (int)breakln_signo;
            }
            break;
        }
    }
    dyn_pathbuf_free(&storage_name1);
    dyn_pathbuf_free(&storage_name2);
    return ret;
}
