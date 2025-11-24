/*

    breaklink : Efficient hard link breaking utility

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

#include <assert.h>
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
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/fs.h>

#define BREAKLN_EXIT_OK 0
#define BREAKLN_EXIT_FAIL_SAFE 1
#define BREAKLN_EXIT_FAIL_UNSAFE 2

/***
    Dynamic Path Buffers

    We avoid dynamic allocation of buffers as possible
    (use static storage instead).
    Still, there's a case where allocation will be needed.
***/

struct dyn_pathbuf {
    // Dynamic buffer (if longer than PATH_MAX)
    char* dyn;
    // Allocated dynamic buffer size (in chars excluding trailing NUL)
    size_t dyn_chars;
    // Static buffer
    char buf[PATH_MAX + 1];
};

static void
dyn_pathbuf_init(struct dyn_pathbuf* buf)
{
    buf->dyn = NULL;
    buf->dyn_chars = 0;
    buf->buf[0] = '\0';
}

static char*
dyn_pathbuf_strdup(struct dyn_pathbuf* buf, const char* pathname, size_t pathlen)
{
    if (buf->dyn && buf->dyn_chars >= pathlen) {
        // Reuse existing allocated buffer (do not update dyn_chars).
        strcpy(buf->dyn, pathname);
        return buf->dyn;
    } else if (pathlen <= PATH_MAX) {
        // Use static buffer.
        strcpy(buf->buf, pathname);
        return buf->buf;
    } else {
        // Newly allocate buffer.
        if (buf->dyn)
            free(buf->dyn);
        buf->dyn = strdup(pathname);
        buf->dyn_chars = pathlen;
        return buf->dyn;
    }
}

static void
dyn_pathbuf_free(struct dyn_pathbuf* buf)
{
    if (buf->dyn) {
        free(buf->dyn);
        buf->dyn = NULL;
    }
}

static struct dyn_pathbuf storage_name1; // dirname
static struct dyn_pathbuf storage_name2; // basename
static char procfd_name[PATH_MAX + 1]; // graceful recovery (static only)

/***
    Command Line Parser
***/

static const char* cmdname = PACKAGE_NAME;

static void fatal_navigate_to_help(void)
{
    fprintf(stderr, "Try '%s --help' for more information.\n", cmdname);
    exit(1);
}

static void fatal_unknown_option(const char* option)
{
    fprintf(stderr, "%s: unrecognized option '%s'\n", cmdname, option);
    fatal_navigate_to_help();
}

static char** files = NULL;
static int files_count = 0;

void parse_cmdline(int argc, char** argv)
{
    bool is_help = false;
    bool is_version = false;
    if (argc > 0)
        cmdname = argv[0];

    for (argv++, argc--; argc > 0; argv++, argc--) {
        char* opt = *argv;
        if (opt[0] == '-') {
            // opt matches /^-.*/.
            if (opt[1] == '-') {
                // Parse long options
                char* optname = opt + 2;
                if (*optname == '\0') {
                    // -- : Break parser
                    argv++;
                    argc--;
                    break;
                } else if (strcmp(optname, "help") == 0) {
                    // --help : Display help
                    is_help = true;
                } else if (strcmp(optname, "version") == 0) {
                    // --version : Display version
                    is_version = true;
                } else {
                    // Unknown long option
                    fatal_unknown_option(opt);
                }
            } else {
                // Parse short options : not yet implemented!
                fatal_unknown_option(opt);
            }
        } else {
            // opt does not start with a hyphen: consider as file name.
            break;
        }
    }

    // Process `--help` and `--version`
    if (is_help) {
        fprintf(
            stderr,
            "Usage: %s [OPTION...] [--] FILE...\n"
            "Break hard links of regular FILE(s).\n"
            "\n"
            "\t--help     Display help\n"
            "\t--version  Display version\n"
            "\n"
            "EXIT STATUS:\n"
            "\t0  Success\n"
            "\t1  Failure (but safe revert succeeded)\n"
            "\t2  Failure (and safe revert failed)\n",
            cmdname);
    }
    if (is_version) {
        fputs(PACKAGE_NAME " version " PACKAGE_VERSION "\n"
                           "\n"
                           "Website: <" PACKAGE_URL ">\n",
            stderr);
    }
    if (is_help || is_version)
        exit(0);

    // Process files list (error if empty)
    files = argv;
    files_count = argc;
    if (files_count == 0) {
        fprintf(stderr, "%s: missing operand\n", cmdname);
        fatal_navigate_to_help();
    }
}

/***
    Break hard links (breakln command)
***/

// For graceful recovery on interruption and other handlings.
static volatile sig_atomic_t breakln_interrupted = 0;
static volatile sig_atomic_t breakln_signo = 0;
static struct sigaction breakln_osa_i;
static struct sigaction breakln_osa_t;

static void breakln_interrupt_handler(int signo)
{
    breakln_signo = (sig_atomic_t)signo;
    breakln_interrupted = 1;
}

static void breakln_interrupt_enter(void)
{
    struct sigaction sigact;
    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_handler = breakln_interrupt_handler;
    sigemptyset(&sigact.sa_mask);
    sigaddset(&sigact.sa_mask, SIGINT);
    sigaddset(&sigact.sa_mask, SIGTERM);
    sigaction(SIGINT, &sigact, &breakln_osa_i);
    sigaction(SIGTERM, &sigact, &breakln_osa_t);
}

static void breakln_interrupt_leave(void)
{
    sigaction(SIGINT, &breakln_osa_i, NULL);
    sigaction(SIGTERM, &breakln_osa_t, NULL);
}

int process_file(char* pathname)
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
    int dirfd = open(filedir, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        fprintf(
            stderr, "%s: Cannot open directory (%s).\n",
            filedir, strerror(errno));
        goto out0;
    }

    // Check if the file is opened and the metadata can be read.
    int fd = openat(dirfd, filename, O_RDONLY | O_NOFOLLOW);
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
    if (unlinkat(dirfd, filename, 0) < 0) {
        fprintf(
            stderr, "%s: Failed to \"remove\" the original file (%s).\n",
            pathname, strerror(errno));
        goto out2;
    }

    // From here, some operations are dangerous.
    ret = BREAKLN_EXIT_FAIL_UNSAFE;

    // Create file with the same name as the original.
    int fd2 = openat(dirfd, filename, O_WRONLY | O_CREAT, (mode_t)0600);
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
        if (unlinkat(dirfd, filename, 0) < 0) {
            fprintf(
                stderr, "%s (ino=%" PRIuMAX "): Failed to remove invalid file on graceful recovery (%s).\n",
                pathname, fino, strerror(errno));
            goto out2;
        }

        // Try to relink the original file
        if (linkat(AT_FDCWD, procfd_name, dirfd, filename, AT_SYMLINK_FOLLOW) < 0) {
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
    close(dirfd);
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
