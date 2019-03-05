/*
   american fuzzy lop - LLVM instrumentation bootstrap
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is the rewrite of afl-as.h's main_payload.

*/

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "../../afl/config.h"

u8* __afl_area_ptr = 0;
__thread u32 __afl_prev_loc;

bool __afl_use_fork_server = false;

static void __afl_map_shm(void) {
    u8 *id_str = getenv(SHM_ENV_VAR);

    if (id_str) {
        u32 shm_id = atoi(id_str);

        __afl_area_ptr = shmat(shm_id, NULL, 0);

        /* Whooooops. */
        if (__afl_area_ptr == (void *)-1) _exit(1);

        /* Write something into the bitmap so that even with low AFL_INST_RATIO,
           our parent doesn't give up on us. */

        __afl_area_ptr[0] = 1;
    }
}

static void __afl_start_forkserver(void) {
    static u8 tmp[4];
    s32 child_pid;

    u8  child_stopped = 0;

    /* Phone home and tell the parent that we're OK. If parent isn't there,
       assume we're not running in forkserver mode and just execute program. */

    if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

    __afl_use_fork_server = true;

    while (1) {
        u32 was_killed;
        int status;

        /* Wait for parent by reading from the pipe. Abort if read fails. */
        if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);

        /* If we stopped the child in persistent mode, but there was a race
           condition and afl-fuzz already issued SIGKILL, write off the old
           process. */

        if (child_stopped && was_killed) {
            child_stopped = 0;
            if (waitpid(child_pid, &status, 0) < 0) _exit(1);
        }

        if (!child_stopped) {
            /* Once woken up, create a clone of our process. */
            child_pid = fork();
            if (child_pid < 0) _exit(1);

            /* In child process: close fds, resume execution. */
            if (!child_pid) {
                close(FORKSRV_FD);
                close(FORKSRV_FD + 1);

                return;
            }
        } else {
            /* Special handling for persistent mode: if the child is alive but
               currently stopped, simply restart it with SIGCONT. */
            kill(child_pid, SIGCONT);
            child_stopped = 0;
        }

        /* In parent process: write PID to pipe, then wait for child. */
        if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);

        if (waitpid(child_pid, &status, WUNTRACED) < 0)
            _exit(1);

        /* In persistent mode, the child stops itself with SIGSTOP to indicate
           a successful run. In this case, we want to wake it up without forking
           again. */
        if (WIFSTOPPED(status)) child_stopped = 1;

        /* Relay wait status to pipe, then loop back. */
        if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);
    }
}

/* A simplified persistent mode handler, used as explained in README.llvm. */
int __afl_persistent_loop(unsigned int max_cnt) {
    static u8  first_pass = 1;
    static u32 cycle_cnt = 0;

    if (first_pass) {
        /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
           On subsequent calls, the parent will take care of that, but on the first
           iteration, it's our job to erase any trace of whatever happened
           before the loop. */

        if (__afl_area_ptr) {
            memset(__afl_area_ptr, 0, MAP_SIZE);

            __afl_area_ptr[0] = 1;
            __afl_prev_loc = 0;

            cycle_cnt  = __afl_use_fork_server ? max_cnt : 1;
        }
        else { // Terminate after first run
            cycle_cnt = 1;
        }

        first_pass = 0;
        return 1;
    }

    if (--cycle_cnt) {
        raise(SIGSTOP);

        __afl_area_ptr[0] = 1;
        __afl_prev_loc = 0;

        return 1;
    } else {
        /* When exiting __AFL_LOOP(), make sure that the subsequent code that
           follows the loop is not traced. We do that by pivoting back to the
           dummy output region. */

        __afl_area_ptr = 0;
    }

    return 0;
}

void __afl_manual_init(void) {
    static u8 init_done;

    if (!init_done) {
        __afl_map_shm();
        __afl_start_forkserver();

        init_done = 1;
    }
}

__attribute__((constructor)) void __afl_auto_init(void) {
    if (getenv(DEFER_ENV_VAR)) return;

    __afl_manual_init();
}