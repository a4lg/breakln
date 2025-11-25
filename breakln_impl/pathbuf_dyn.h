/*

    breakln : Efficient hard link breaking utility

    breakln_impl/pathbuf_dyn.h
    Dynamic path buffer library

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

#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

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
