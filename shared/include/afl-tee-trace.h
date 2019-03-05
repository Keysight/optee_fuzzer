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

#define CMD_BUF_SIZE(ptr) \
    ((ptr) ? ((uintptr_t)ptr ## _last_append_p - (uintptr_t)ptr) : 0)

#define DATA_BUF_SIZE(ptr) \
    ((ptr) ? ((uintptr_t)ptr ## _append_p - (uintptr_t)ptr) : 0)

#define CMD_BUF_APPEND(ptr, scn, type) \
    /*EMSG("CMD: %x %x", scn, type); */ \
    \
    ((SYSCALL_INVOKE*)ptr)->nr = scn; \
    ((SYSCALL_INVOKE*)ptr)->arg_type = type; \
    \
    ptr = (uintptr_t)ptr + sizeof(SYSCALL_INVOKE);

#define CMD_BUF_APPEND_ARG_VALUE32(ptr, val) \
    EMSG("val32: %x", val); \
    \
    *((uint32_t*)ptr) = val; \
    \
    ptr = (uintptr_t)ptr + arg_size(ARG_VALUE_32);

#define CMD_BUF_APPEND_ARG_BUFFER_ALLOC(ptr, buf_nr, buf_len) \
    EMSG("balloc: %x %x", buf_nr, buf_len); \
    \
    ((SYSCALL_ARG*)ptr)->buffer.nr = buf_nr; \
    ((SYSCALL_ARG*)ptr)->buffer.len = buf_len; \
    \
    ptr = (uintptr_t)ptr + arg_size(ARG_BUFFER_ALLOC);

#define CMD_BUF_APPEND_ARG_BUFFER_REF(ptr, buf_nr, buf_len) \
    EMSG("bref: %x %x", buf_nr, buf_len); \
    \
    ((SYSCALL_ARG*)ptr)->buffer.nr = buf_nr; \
    ((SYSCALL_ARG*)ptr)->buffer.len = buf_len; \
    \
    ptr = (uintptr_t)ptr + arg_size(ARG_BUFFER_REF);

#define CMD_BUF_APPEND_ARG_DATA(ptr, data_offset, data_len) \
    EMSG("dat: %x %x", data_offset, data_len); \
    \
    ((SYSCALL_ARG*)ptr)->data.offset = data_offset; \
    ((SYSCALL_ARG*)ptr)->data.len = data_len; \
    \
    ptr = (uintptr_t)ptr + arg_size(ARG_DATA_PRIVATE);

#define CMD_BUF_APPEND_ARG_DEREF32(ptr, buf_nr) \
    EMSG("dref32: %x", buf_nr); \
    \
    ((SYSCALL_ARG*)ptr)->buffer.nr = buf_nr; \
    ((SYSCALL_ARG*)ptr)->buffer.len = 4; \
    \
    ptr = (uintptr_t)ptr + arg_size(ARG_BUFFER_DEREF32);

#define CMD_BUF_APPEND_ARG_TEE_ATTR(ptr, attr_id, data_offset, data_len) \
    EMSG("attr: %x %x %x", attr_id, data_offset, data_len); \
    \
    ((SYSCALL_ARG*)ptr)->tee_attr.attr = attr_id; \
    ((SYSCALL_ARG*)ptr)->tee_attr.offset = data_offset; \
    ((SYSCALL_ARG*)ptr)->tee_attr.len = data_len; \
    \
    ptr = (uintptr_t)ptr + arg_size(ARG_TEE_ATTR);

#define DATA_BUF_APPEND(buf_ptr, data_ptr, data_len) \
    ({ \
        size_t data_buf_size = (buf_ptr) ? ((uintptr_t)buf_ptr ## _append_p - (uintptr_t)buf_ptr) : 0; \
        \
        EMSG("dat: %p:%x %s", data_ptr, data_len, beautify_data(data_ptr, data_len)); \
        \
        assert(data_ptr != NULL); \
        assert(data_len < 0x10000000); \
        \
        buf_ptr = realloc(buf_ptr, data_buf_size + data_len); \
        buf_ptr ## _append_p = (uintptr_t)buf_ptr + data_buf_size; \
        \
        assert(buf_ptr != NULL); \
        \
        assert(tee_svc_copy_from_user(buf_ptr ## _append_p, data_ptr, data_len) == TEE_SUCCESS); \
        \
        buf_ptr ## _append_p = (uintptr_t)buf_ptr ## _append_p + data_len; \
        \
        data_buf_size; /* offset in data buffer when our data starts */ \
    })
