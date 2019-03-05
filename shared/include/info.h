/*
 * This file is part of the OP-TEE Fuzzer (https://github.com/MartijnB/optee_fuzzer).
 * Copyright (c) 2019 Riscure B.V.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdbool.h>
#include <stdint.h>

#include <tee_syscall_numbers.h>

#define ARG_VALUE 1
#define ARG_VALUE_OUT_PTR 2
#define ARG_VALUE_INOUT_PTR 3
#define ARG_HANDLE 4
#define ARG_HANDLE_OUT_PTR 5
#define ARG_BUF_IN_ADDR 6
#define ARG_BUF_OUT_ADDR 7
#define ARG_BUF_INOUT_ADDR 8

#define ARG_BUF_LEN_ARG(x) ((x+1) << (8))
#define ARG_BUF_TYPE(x) ((x) << (16))
#define ARG_BUF_SIZE(x) ((x) << (24))

#define GET_ARG_BUF_LEN_ARG(x) (((x >> (8)) & 0xFF)-1)
#define GET_ARG_BUF_TYPE(x) ((x >> (16)) & 0xFF)
#define GET_ARG_BUF_SIZE(x) ((x >> (24)) & 0xFF)

#define ARG_TYPE_ATTR 1

typedef struct {
    uint32_t nr;
    uint32_t num_args;
    const char* name;
    uint32_t arg_info[TEE_SVC_MAX_ARGS];

#ifdef TA_BUILD
    const void* fptr;
#endif
} SYSCALL_INFO;

extern SYSCALL_INFO syscalls[];

extern const char* __gi_name[];
extern uint32_t __gi_args[];

#ifdef TA_BUILD
extern const void* __gi_fptr[];
#endif

static const char* syscall_name(uint32_t nr) {
	assert(nr <= TEE_SCN_MAX);

    return __gi_name[nr];
}

static bool syscall_must_skip(uint32_t nr) {
	switch (nr) {
        case TEE_SCN_RETURN:
        //case TEE_SCN_LOG:
        case TEE_SCN_PANIC:
        case TEE_SCN_OPEN_TA_SESSION:
        case TEE_SCN_WAIT:
        case TEE_SCN_GET_TIME:
            return true;
    }

    return false;
}

static uint32_t syscall_num_args(uint32_t nr) {
	assert(nr <= TEE_SCN_MAX);

    return __gi_args[nr];
}

#ifdef TA_BUILD

static const void* syscall_fptr(uint32_t nr) {
	assert(nr <= TEE_SCN_MAX);
	
    return __gi_fptr[nr];
}

static uint64_t syscall_arg_info(uint32_t nr, uint32_t arg_nr);

#endif