/*

    breakln : Efficient hard link breaking utility

    breakln_impl/cmdline.h
    Command line parser

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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
