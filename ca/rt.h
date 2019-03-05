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

#include <sys/types.h>

#include "../../afl/config.h"

#define __AFL_INIT_PERSISTENT() \
	__afl_persistent_init()

#define __AFL_LOOP(A)\
	__afl_persistent_loop(A)

#define __AFL_LOG(L) \
	__afl_log(L)

#define __AFL_LOG_AUTO \
	__AFL_LOG(__COUNTER__)

#define __AFL_INC_BITMAP(I) \
	__afl_inc_bitmap(I)

#define __AFL_SET_BITMAP(I, V) \
  __afl_set_bitmap(I, V)

extern u8* __afl_area_ptr;
extern __thread u32 __afl_prev_loc;

void __afl_persistent_init(void);
int __afl_persistent_loop(unsigned int max_cnt);

static inline void __afl_log(unsigned int cur_loc) __attribute__((always_inline));
static inline void __afl_inc_bitmap(unsigned int loc) __attribute__((always_inline));
static inline void __afl_set_bitmap(unsigned int loc, u8 val) __attribute__((always_inline));

/* The equivalent of the tuple logging routine from afl-as.h. */
static inline void __afl_log(unsigned int cur_loc) {


// QEMU
    {
        /* Optimize for cur_loc > afl_end_code, which is the most likely case on
           Linux systems. */

        //if (cur_loc > afl_end_code || cur_loc < afl_start_code || !afl_area_ptr)
        //  return;
    }

    if (!__afl_area_ptr)
        return;

// QEMU
    {
        /* Looks like QEMU always maps to fixed locations, so ASAN is not a
           concern. Phew. But instruction addresses may be aligned. Let's mangle
           the value to get something quasi-uniform. */

        //cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
        //cur_loc &= MAP_SIZE - 1;

        /* Implement probabilistic instrumentation by looking at scrambled block
           address. This keeps the instrumented locations stable across runs. */

        //if (cur_loc >= afl_inst_rms) return;
    }

    __afl_area_ptr[cur_loc ^ __afl_prev_loc]++;
    __afl_prev_loc = cur_loc >> 1;
}

static inline void __afl_inc_bitmap(unsigned int loc) {
    if (!__afl_area_ptr)
        return;

    __afl_area_ptr[loc % MAP_SIZE]++;
}


static inline void __afl_set_bitmap(unsigned int loc, u8 val) {
    if (!__afl_area_ptr)
        return;

    __afl_area_ptr[loc % MAP_SIZE] = val;
}