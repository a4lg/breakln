#
#   breakln: Efficient hard link breaking utility
#
#   Copyright (C) 2025 Tsukasa OI.
#
#   Permission is hereby granted, free of charge, to any person obtaining a
#   copy of this software and associated documentation files (the "Software"),
#   to deal in the Software without restriction, including without limitation
#   the rights to use, copy, modify, merge, publish, distribute, sublicense,
#   and/or sell copies of the Software, and to permit persons to whom
#   the Software is furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
#   IN THE SOFTWARE.
#

AC_PREREQ([2.70])
AC_INIT([breakln], [0.1.2-alpha.0], [floss_zutils@irq.a4lg.com], [breakln], [https://github.com/a4lg/breakln])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([breakln.c])
AC_CONFIG_HEADERS([config.h])

dnl Assume newer environment with POSIX.1-2008, GNU extension and large file support
AC_DEFINE([_POSIX_C_SOURCE], [200809L], [POSIX.1-2008 support])
AC_DEFINE([_GNU_SOURCE], [1], [GNU extensions of C library])
AC_DEFINE([_FILE_OFFSET_BITS], [64], [Large file support])

AC_PROG_CC
AS_IF([test "x$ac_cv_proc_cc_c11" = xno], [AC_MSG_ERROR([C compiler must support C11.])])

AC_CHECK_HEADERS([fcntl.h libgen.h time.h linux/fs.h],, [
AC_MSG_ERROR([required header file(s) not found.])
])

AC_CHECK_FUNCS([openat dirname copy_file_range nanosleep],, [
AC_MSG_ERROR([required function(s) not found.])
])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
