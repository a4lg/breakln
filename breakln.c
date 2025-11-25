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

// Dynamic path buffer for dirname
static struct dyn_pathbuf storage_name1;
// Dynamic path buffer for basename
static struct dyn_pathbuf storage_name2;
// Static path buffer for graceful recovery
static char procfd_name[PATH_MAX + 1];

// Process a file.
static int process_file(char* pathname)
{
    bool critical_entered = false;
    int ret = BREAKLN_EXIT_FAIL_SAFE;
    size_t pathlen = strlen(pathname);

    // Preprocess paths
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
    char* filedir = dirname(name1_base);
    char* filename = basename(name2_base);

    // Open the directory.
    int fd_dir = open(filedir, O_RDONLY | O_DIRECTORY);
    if (fd_dir < 0) {
        fprintf(
            stderr, "%s: Cannot open directory (%s).\n",
            filedir, strerror(errno));
        goto out0;
    }

    // Check if the file is opened and the metadata can be read.
    int fd = openat(fd_dir, filename, O_RDONLY | O_NOFOLLOW);
    struct stat fst;
    if (fd < 0) {
        fprintf(
            stderr, "%s: %s.\n", pathname,
            errno == ELOOP
                ? "Symbolic link is not supported"
                : strerror(errno));
        goto out1;
    }
    if (fstat(fd, &fst) < 0) {
        fprintf(
            stderr, "%s: %s.\n", pathname,
            strerror(errno));
        goto out2;
    }
    uintmax_t fino = (uintmax_t)fst.st_ino;

    // Only regular files are supported.
    if (!S_ISREG(fst.st_mode)) {
        fprintf(stderr, "%s: Only regular files are supported.\n", pathname);
        goto out2;
    }

    // Skip if there's no need to break hard links.
    if (fst.st_nlink <= 1) {
        ret = BREAKLN_EXIT_OK;
        goto out2;
    }

    /*
        Operating Mode: Minimum File System Disruption.
    */

    // Enter the critical section.
    breakln_interrupt_enter();
    critical_entered = true;

    // Remove the original file (path).
    if (unlinkat(fd_dir, filename, 0) < 0) {
        fprintf(
            stderr, "%s: Failed to \"remove\" the original file (%s).\n",
            pathname, strerror(errno));
        goto out2;
    }

    // From here, some operations are dangerous.
    ret = BREAKLN_EXIT_FAIL_UNSAFE;

    // Create file with the same name as the original.
    int fd2 = openat(fd_dir, filename, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, (mode_t)0600);
    if (fd2 < 0) {
        fprintf(
            stderr, "%s (ino=%" PRIuMAX "): Failed to create destination without hard links (%s).\n",
            pathname, fino, strerror(errno));
        goto out2;
    }

    // Check if the original file is empty.
    if (fst.st_size == 0) {
        // Empty file and subsequent cloning operations not needed.
        ret = BREAKLN_EXIT_OK;
        goto out3;
    }

#ifdef FICLONE
    // Clone the file as possible.
    if (ioctl(fd2, FICLONE, fd) >= 0) {
        // FICLONE succeeded!
        ret = BREAKLN_EXIT_OK;
        goto out3;
    }
#endif

    // FICLONE is either not supported or failed.
    // Use copy_file_range instead.

    // Get maximum chunk size.
    size_t max_chunk_size = SIZE_MAX;
    {
        // Align to the page size if possible.
        long val = sysconf(_SC_PAGESIZE);
        if (val > 0) {
            size_t pagesize = val;
            max_chunk_size = max_chunk_size / pagesize * pagesize;
        }
    }

    // Interrupt
    if (breakln_interrupted) {
        fprintf(stderr, "%s (ino=%" PRIuMAX "): Interrupted while processing.\n",
            pathname, fino);
        goto out3;
    }

    // Truncate (for partial failure of FICLONE).
    if (lseek(fd2, 0, SEEK_SET) == -1 || ftruncate(fd2, 0) < 0) {
        fprintf(
            stderr, "%s (ino=%" PRIuMAX "): Failed to prepare regular file copy (%s).\n",
            pathname, fino, strerror(errno));
        goto out3;
    }

    // Copy file ranges.
    off_t filesize = fst.st_size;
    ssize_t chunk;
    do {
        // Interrupt
        if (breakln_interrupted) {
            fprintf(stderr, "%s (ino=%" PRIuMAX "): Interrupted while processing.\n",
                pathname, fino);
            goto out3;
        }

        /*
            Portability Note:
            Even on the worst case, comparison between different integer
            types are safe as long as the both operands are non-negative.
        */
        size_t sz = filesize >= max_chunk_size
            ? max_chunk_size
            : (size_t)filesize;
        chunk = copy_file_range(fd, NULL, fd2, NULL, sz, 0);
        if (chunk < 0) {
            fprintf(
                stderr, "%s (ino=%" PRIuMAX "): Failed to copy from the original file (%s).\n",
                pathname, fino, strerror(errno));
            goto out3;
        }
        filesize -= (off_t)chunk;
    } while (filesize > 0 && chunk > 0);

    // Finalization
    ret = BREAKLN_EXIT_OK;
out3:
    if (ret == BREAKLN_EXIT_OK) {
        // Finalization: chmod to the original mode
        if (fchmod(fd2, fst.st_mode & ~(mode_t)S_IFMT) < 0) {
            fprintf(
                stderr, "%s: Break link complete but failed to restore permission flags (%s).\n",
                pathname, strerror(errno));
            ret = BREAKLN_EXIT_FAIL_SAFE;
        }

        // Finalization: chown to the original owner (can fail)
        if (fchown(fd2, fst.st_uid, fst.st_gid) < 0) {
            fprintf(
                stderr, "%s: (warning) Break link complete but failed to change its owner (%s).\n",
                pathname, strerror(errno));
            // Don't set error here.
        }
    }

    close(fd2);

    if (ret == BREAKLN_EXIT_FAIL_UNSAFE) {
        // Attempt graceful recovery (from an unsafe failure).
        // Precondition:
        // If we enter here, we have a file with the same name.
        int sz = snprintf(procfd_name, PATH_MAX + 1, "/proc/self/fd/%d", fd);
        if (sz > PATH_MAX) {
            // Cannot format /proc/self/fd/%d (nearly impossible to happen).
            fprintf(
                stderr, "%s (ino=%" PRIuMAX "): Cannot format path for graceful recovery (%s).\n",
                pathname, fino, strerror(errno));
            goto out2;
        }

        // First, remove the invalid file.
        if (unlinkat(fd_dir, filename, 0) < 0) {
            fprintf(
                stderr, "%s (ino=%" PRIuMAX "): Failed to remove invalid file on graceful recovery (%s).\n",
                pathname, fino, strerror(errno));
            goto out2;
        }

        // Try to relink the original file
        if (linkat(AT_FDCWD, procfd_name, fd_dir, filename, AT_SYMLINK_FOLLOW) < 0) {
            fprintf(
                stderr, "%s (ino=%" PRIuMAX "): Failed to perform graceful recovery (%s).\n",
                pathname, fino, strerror(errno));
            goto out2;
        }

        // Now, we have failed to break a hard link
        // but at least succeeded to revert the state.
        ret = BREAKLN_EXIT_FAIL_SAFE;
    }
out2:
    close(fd);
    if (critical_entered)
        breakln_interrupt_leave();
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
