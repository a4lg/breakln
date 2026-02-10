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

#include <stdbool.h>
#include <string.h>

#include <signal.h>

// For graceful recovery on interruption and other handlings.
static volatile sig_atomic_t breakln_interrupted = 0;
static volatile sig_atomic_t breakln_signo = SIGINT;
static struct sigaction breakln_orig_action_int;
static struct sigaction breakln_orig_action_term;
static bool breakln_is_interrupt_context = false;

static void breakln_interrupt_handler(int signo)
{
    breakln_signo = (sig_atomic_t)signo;
    breakln_interrupted = 1;
}

static bool breakln_interrupt_enter(void)
{
    struct sigaction sigact = {};
    sigact.sa_handler = breakln_interrupt_handler;
    if (sigemptyset(&sigact.sa_mask) < 0
        || sigaddset(&sigact.sa_mask, SIGINT) < 0
        || sigaddset(&sigact.sa_mask, SIGTERM) < 0)
        return false;
    if (sigaction(SIGINT, &sigact, &breakln_orig_action_int) < 0)
        return false;
    if (sigaction(SIGTERM, &sigact, &breakln_orig_action_term) < 0) {
        // sigaction can fail but we don't care that much in this path.
        sigaction(SIGINT, &breakln_orig_action_int, NULL);
        return false;
    }
    breakln_is_interrupt_context = true;
    return true;
}

static void breakln_interrupt_leave(void)
{
    if (!breakln_is_interrupt_context)
        return;
    // sigaction can fail but we don't care that much in this path.
    sigaction(SIGINT, &breakln_orig_action_int, NULL);
    sigaction(SIGTERM, &breakln_orig_action_term, NULL);
    breakln_is_interrupt_context = false;
}
