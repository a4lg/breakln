/*

    breakln : Efficient hard link breaking utility

    breakln_impl/signal_handler.h
    Signal handling components

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

#include <string.h>

#include <signal.h>

// For graceful recovery on interruption and other handlings.
static volatile sig_atomic_t breakln_interrupted = 0;
static volatile sig_atomic_t breakln_signo = SIGINT;
static struct sigaction breakln_orig_action_int;
static struct sigaction breakln_orig_action_term;

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
    sigaction(SIGINT, &sigact, &breakln_orig_action_int);
    sigaction(SIGTERM, &sigact, &breakln_orig_action_term);
}

static void breakln_interrupt_leave(void)
{
    sigaction(SIGINT, &breakln_orig_action_int, NULL);
    sigaction(SIGTERM, &breakln_orig_action_term, NULL);
}
