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

#ifndef __AFL_TEE_H
#define __AFL_TEE_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#if defined(__KERNEL__) || defined(TA_BUILD)
#include <trace.h>
#if defined(__KERNEL__)
#define printf(...)
#endif
#else
#define DMSG printf
#define IMSG printf
#define EMSG printf
#endif

#include "info.h"
#include "fmt.h"
#include "utils.h"

#define MAX_BUF_COUNT 1024

#define MAX_CALLS 1024

typedef enum {
    ARG_NONE,

    ARG_VALUE_NULL,         // 1
    ARG_VALUE_8,            // 2
    ARG_VALUE_16,           // 3
    ARG_VALUE_32,           // 4
    ARG_VALUE_64,           // 5

    ARG_BUFFER_ALLOC,       // 6
    ARG_BUFFER_REF = 13,    // 13 (todo: renumber)
    ARG_BUFFER_DEREF32 = 7, // 7
    ARG_BUFFER_DEREF64,     // 8

    ARG_DATA_SHARED,        // 9
    ARG_DATA_PRIVATE,       // 10

    ARG_RETURN_VALUE,       // 11

    ARG_TEE_ATTR,           // 12, Special type for op-tee

    ARG_TYPE_MAX = 14
} SYSCALL_ARG_TYPE;

typedef union {
    uint8_t val8;
    uint16_t val16;
    uint32_t val32;
    uint64_t val64;

    struct {
        uint32_t offset : 20;
        uint32_t len : 12;
    } data;

    struct {
        uint32_t nr : 12;
        uint32_t len : 20;
    } buffer;

    uint16_t ret_val; // RETURN VALUE

    struct {
        uint32_t attr;
        uint32_t offset : 20;
        uint32_t len : 12;
    } tee_attr;
} SYSCALL_ARG __attribute__ (( aligned(4) ));

typedef struct {
    uint8_t nr;

    uint8_t __pad[3]; // It seems it's cheaper to have aligned accesses with 3 pad bytes than unaligned mem

    uint32_t arg_type; /* arg_type[TEE_SVC_MAX_ARGS]; */

    SYSCALL_ARG args[]; /* args[TEE_SVC_MAX_ARGS]; */
} SYSCALL_INVOKE __attribute__ (( aligned(8) ));

typedef struct {
    const void* const buf;
    const size_t buf_len;

    const SYSCALL_INVOKE* const cmd_first;
    const SYSCALL_INVOKE* cmd_current;

    const void* const data;
    const size_t data_len;

    char** p_error;
} CTX;

typedef const CTX* const CTX_CP;

#define CMD_CTX_CLONE(ctx, ctx_new) \
    CTX (ctx_new) = { \
        .buf = (ctx)->buf, \
        .buf_len = (ctx)->buf_len, \
        \
        .cmd_first = (ctx)->cmd_first, \
        .cmd_current = (ctx)->cmd_current, \
        \
        .data = (ctx)->data, \
        .data_len = (ctx)->data_len, \
        \
        .p_error = (ctx)->p_error \
    };

#define CMD_CURRENT(ctx) \
    ((ctx)->cmd_current)

#define CMD_RESET_CURRENT(ctx) \
    do { \
        (ctx)->cmd_current = NULL; \
    } \
    while (0);

#define CMD_OR_NULL(ctx, p) \
    (( \
        (ctx)->buf <= ((void*)(p)) && \
        (uint8_t*)(((uint8_t*)(p)) + sizeof(SYSCALL_INVOKE)) <= ((uint8_t*)(ctx)->buf + (ctx)->buf_len) && \
        ((SYSCALL_INVOKE*)(p))->nr <= TEE_SCN_MAX  && /* 0xFFFF == end */ \
        (uint8_t*)(((uint8_t*)(p)) + invoke_entry_size((SYSCALL_INVOKE*)(p))) <= ((uint8_t*)(ctx)->buf + (ctx)->buf_len) \
     ) \
     ? ((SYSCALL_INVOKE*)(p)) \
     : NULL)

#define CMD_NEXT(ctx) \
    ((ctx)->cmd_current = (ctx)->cmd_current == NULL \
                          ? CMD_OR_NULL(ctx, ((ctx)->cmd_first)) \
                          : CMD_OR_NULL(ctx, (((uint8_t *) (ctx)->cmd_current) + invoke_entry_size((ctx)->cmd_current))))

#define CMD_DATA_PTR(ctx, off) \
    (&((uint8_t*)ctx->data)[off])

static char __cmd_err_msg[128];

#define CMD_ERR(ctx, ...) \
    do { \
        if ((ctx)->p_error != NULL) { \
            snprintf(__cmd_err_msg, sizeof(__cmd_err_msg), __VA_ARGS__); \
            *(ctx)->p_error = __cmd_err_msg; \
        } \
    } \
    while (0);

#define IS_VALID_ARG_TYPE(t) ((t) < ARG_TYPE_MAX)

#define GET_ARG_TYPE(t, n) ((const SYSCALL_ARG_TYPE)(((t) >> ((n) * 4u)) & 0xFu))
#define SET_ARG_TYPE(v, n, t) \
    do { \
        \
        assert(n < 8); \
        \
        (v) = (((v) & ~(0xFu << ((n)*4u))) | (((t) & 0xFu) << (n * 4u))); \
    } while(0);

#define SVC_FOREACH_ARG(syscall, start, len, p_arg, arg_type, b) \
    do { \
        const SYSCALL_ARG* (p_arg) = &(syscall)->args[0]; \
        \
        for (uint32_t arg_nr = start; arg_nr < len; arg_nr++) { \
            const SYSCALL_ARG_TYPE arg_type = GET_ARG_TYPE((syscall)->arg_type, arg_nr); \
            \
            b \
            \
            (p_arg) = (SYSCALL_ARG*)(((uint8_t*)(p_arg)) + arg_size(arg_type)); \
        } \
    } \
    while (0);

#define SVC_FOREACH_ARG_UNTIL_VAL_NONE(syscall, p_arg, arg_type, b) \
    do { \
        const SYSCALL_ARG* (p_arg) = &(syscall)->args[0]; \
        \
        for (uint32_t arg_nr = 0; arg_nr < TEE_SVC_MAX_ARGS; arg_nr++) { \
            const SYSCALL_ARG_TYPE arg_type = GET_ARG_TYPE((syscall)->arg_type, arg_nr); \
            \
            /* break if ARG_NONE */ \
            if (arg_type == ARG_NONE) { break; } \
            \
            b \
            \
            (p_arg) = (SYSCALL_ARG*)(((uint8_t*)(p_arg)) + arg_size(arg_type)); \
        } \
    } \
    while (0);

bool is_buffer_used_after(const CTX* ctx, uint32_t buf_nr);

bool is_valid_cmd_buf(const void *buf, size_t buf_len, char **p_error);

static inline size_t arg_size(const SYSCALL_ARG_TYPE arg_type) {
    switch (arg_type) {
        case ARG_NONE:
        case ARG_VALUE_NULL:
            return 0;
        case ARG_VALUE_8:
            //return sizeof(((SYSCALL_ARG *)0)->val8);
        case ARG_VALUE_16:
            //return sizeof(((SYSCALL_ARG *)0)->val16);
        case ARG_VALUE_32:
            return sizeof(((SYSCALL_ARG *)0)->val32);
        case ARG_VALUE_64:
            return sizeof(((SYSCALL_ARG *)0)->val64);
        case ARG_RETURN_VALUE:
            return sizeof(((SYSCALL_ARG *)0)->ret_val);
        case ARG_BUFFER_ALLOC:
        case ARG_BUFFER_REF:
        case ARG_BUFFER_DEREF32:
        case ARG_BUFFER_DEREF64:
            return sizeof(((SYSCALL_ARG *)0)->buffer);
        case ARG_DATA_SHARED:
        case ARG_DATA_PRIVATE:
            return sizeof(((SYSCALL_ARG *)0)->data);
        case ARG_TEE_ATTR:
            return sizeof(((SYSCALL_ARG *)0)->tee_attr);
        default:
            return 0; // ?!?!

            //printf("Unexpected arg type: %x", arg_type);
            //assert(0);
    }
}

static inline size_t invoke_entry_size(const SYSCALL_INVOKE* syscall) {
    size_t size = sizeof(SYSCALL_INVOKE);

    assert(syscall_num_args(syscall->nr) <= TEE_SVC_MAX_ARGS);

    for (uint32_t arg_nr = 0; arg_nr < syscall_num_args(syscall->nr); arg_nr++) {
        if (IS_VALID_ARG_TYPE(GET_ARG_TYPE(syscall->arg_type, arg_nr))) {
            size += arg_size(GET_ARG_TYPE(syscall->arg_type, arg_nr));
        }
    }

    return size;
}

static inline size_t max_invoke_entry_size(void) {
    return sizeof(SYSCALL_INVOKE) + (TEE_SVC_MAX_ARGS * sizeof(SYSCALL_ARG));
}

#endif