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

#include <string.h>
#include <trace.h>
#include <assert.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <utee_types.h>
#include <utee_syscalls.h>

#include <afl-tee.h>

char* g_buf[MAX_BUF_COUNT];
char* g_tmp_buf[TEE_SVC_MAX_ARGS];

uint64_t g_ret_val[MAX_CALLS];

static inline void print_invoke_syscall_info(uint32_t scn, uint32_t* args) {
    static char buf[256] = {0};
    size_t len = 0;

    len += snprintf(buf + len, sizeof(buf) - len, "%s[%i](", syscall_name(scn), scn);

    for (int i = 0; i < syscall_num_args(scn); i++) {
        if (i >= 1) {
            len += snprintf(buf + len, sizeof(buf) - len, ", ");
        }

        len += snprintf(buf + len, sizeof(buf) - len, "%x", args[i]);
    }

    len += snprintf(buf + len, sizeof(buf) - len, ")");

    utee_log(buf, len);
}

static inline void print_post_invoke_syscall_info(uint32_t scn, uint32_t* args, uint32_t ret_val) {
    if (ret_val == TEE_SUCCESS) {
        switch (scn) {
            case TEE_SCN_STORAGE_ENUM_ALLOC:
            case TEE_SCN_SE_SERVICE_OPEN:
                printf(" [*%p = %x]\n", args[0], *((uint32_t*)args[0]));
                break;

            case TEE_SCN_CRYP_OBJ_ALLOC:
                printf(" [*%p = %x]\n", args[2], *((uint32_t*)args[2]));
                break;

            case TEE_SCN_CRYP_STATE_ALLOC:
            case TEE_SCN_STORAGE_OBJ_OPEN:
                printf(" [*%p = %x]\n", args[4], *((uint32_t*)args[4]));
                break;

            case TEE_SCN_STORAGE_OBJ_CREATE:
                printf(" [*%p = %x]\n", args[7], *((uint32_t*)args[7]));
                break;

            default:
                printf("\n");
                break;
        }
    }
    else {
        printf(" -> %s\n", gp_format_return_code(ret_val));
    }
}

static uint64_t do_invoke_syscall(uint32_t scn, uint32_t* args) {
    uint32_t num_args = syscall_num_args(scn);
    void *funcPtr = syscall_fptr(scn);

#if CFG_TEE_TA_LOG_LEVEL > 1
    print_invoke_syscall_info(scn, args);
#endif

    uint32_t(*syscallPtr)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t) = funcPtr;

    uint32_t ret_val = syscallPtr(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);

#if CFG_TEE_TA_LOG_LEVEL > 1
    print_post_invoke_syscall_info(scn, args, ret_val);
#endif

    return ret_val;
}

static void invoke_syscall(CTX_CP ctx, uint64_t* ret_val_p) {
    const SYSCALL_INVOKE* const sys_invoke_p = CMD_CURRENT(ctx);

    assert(syscall_num_args(sys_invoke_p->nr) <= TEE_SVC_MAX_ARGS);
    assert(!syscall_must_skip(sys_invoke_p->nr)); // slips sometimes through validation

    uint32_t args[TEE_SVC_MAX_ARGS] = {0};

    static struct utee_attribute tee_attr;

    SYSCALL_ARG* p_arg = &sys_invoke_p->args[0];

    for (uint32_t arg_nr = 0; arg_nr < syscall_num_args(sys_invoke_p->nr); arg_nr++) {
        SYSCALL_ARG_TYPE arg_type = GET_ARG_TYPE(sys_invoke_p->arg_type, arg_nr);

        assert(arg_type != ARG_NONE);

        switch (arg_type) {
            case ARG_VALUE_NULL:
                // No need to explicitly set it to 0 as it is already done by memsetting all args during the declaration
                break;

            case ARG_VALUE_8:
                args[arg_nr] = (uint32_t)p_arg->val8;
                break;

            case ARG_VALUE_16:
                args[arg_nr] = (uint32_t)p_arg->val16;
                break;

            case ARG_VALUE_32:
                args[arg_nr] = (uint32_t)p_arg->val32;
                break;

            case ARG_VALUE_64:
                args[arg_nr] = (uint32_t)p_arg->val64;
                break;

            case ARG_RETURN_VALUE:
                args[arg_nr] = (uint32_t) g_ret_val[p_arg->ret_val];
                break;

            case ARG_BUFFER_ALLOC:
            case ARG_BUFFER_REF:
                args[arg_nr] = (uint32_t)g_buf[p_arg->buffer.nr];
                break;

            case ARG_BUFFER_DEREF32:
                assert(g_buf[p_arg->buffer.nr] != NULL);

                memcpy(&args[arg_nr], g_buf[p_arg->buffer.nr], 4);
                break;

            case ARG_BUFFER_DEREF64:
                assert(g_buf[p_arg->buffer.nr] != NULL);

                memcpy(&args[arg_nr], g_buf[p_arg->buffer.nr], 8);
                break;

            case ARG_DATA_SHARED:
                args[arg_nr] = (uint32_t)CMD_DATA_PTR(ctx, p_arg->data.offset);
                break;

            case ARG_DATA_PRIVATE:
                args[arg_nr] = (uint32_t)g_tmp_buf[arg_nr];
                break;

            case ARG_TEE_ATTR:
                tee_attr.attribute_id = p_arg->tee_attr.attr;
                tee_attr.a = (uint32_t)CMD_DATA_PTR(ctx, p_arg->data.offset);
                tee_attr.b = (uint32_t)p_arg->tee_attr.len;

                args[arg_nr] = &tee_attr;
                break;
        }

        p_arg = (SYSCALL_ARG*)(((char*)p_arg) + arg_size(GET_ARG_TYPE(sys_invoke_p->arg_type, arg_nr)));
    }

    *ret_val_p = do_invoke_syscall(sys_invoke_p->nr, args);
}

static void pre_invoke_syscall(CTX_CP ctx) {
    const SYSCALL_INVOKE* const sys_invoke_p = CMD_CURRENT(ctx);

    assert(syscall_num_args(sys_invoke_p->nr) <= TEE_SVC_MAX_ARGS);

    SYSCALL_ARG* p_arg = &sys_invoke_p->args[0];

    for (uint32_t arg_nr = 0; arg_nr < syscall_num_args(sys_invoke_p->nr); arg_nr++) {
        SYSCALL_ARG_TYPE arg_type = GET_ARG_TYPE(sys_invoke_p->arg_type, arg_nr);

        assert(arg_type != ARG_NONE);

        switch (arg_type) {
            case ARG_BUFFER_ALLOC: {
                if (!g_buf[p_arg->buffer.nr]) {
                    uint32_t buf_nr = p_arg->buffer.nr;
                    uint32_t buf_len = p_arg->buffer.len;

                    g_buf[buf_nr] = malloc(buf_len);

                    assert(g_buf[buf_nr] != NULL);
                }
                break;
            }

            case ARG_DATA_PRIVATE: {
                uint32_t data_offset = p_arg->data.offset;
                uint32_t data_len = p_arg->data.len;

                g_tmp_buf[arg_nr] = malloc(data_len);

                assert(g_tmp_buf[arg_nr] != NULL);

                memcpy(g_tmp_buf[arg_nr], CMD_DATA_PTR(ctx, data_offset), data_len);
                break;
            }
        }

        p_arg = (SYSCALL_ARG*)(((char*)p_arg) + arg_size(GET_ARG_TYPE(sys_invoke_p->arg_type, arg_nr)));
    }
}

static void post_invoke_syscall(CTX_CP ctx) {
    const SYSCALL_INVOKE* const sys_invoke_p = CMD_CURRENT(ctx);

    SYSCALL_ARG* p_arg = &sys_invoke_p->args[0];

    assert(syscall_num_args(sys_invoke_p->nr) <= TEE_SVC_MAX_ARGS);

    for (uint32_t arg_nr = 0; arg_nr < syscall_num_args(sys_invoke_p->nr); arg_nr++) {
        SYSCALL_ARG_TYPE arg_type = GET_ARG_TYPE(sys_invoke_p->arg_type, arg_nr);

        assert(arg_type != ARG_NONE);

        switch (arg_type) {
            case ARG_BUFFER_ALLOC:
            case ARG_BUFFER_REF:
            case ARG_BUFFER_DEREF32:
            case ARG_BUFFER_DEREF64: {
                    // Cleanup no longer needed buffers
                    uint32_t buf_nr = p_arg->buffer.nr;

                    if (g_buf[p_arg->buffer.nr]) {
                        if (!is_buffer_used_after(ctx, buf_nr)) {
                            free(g_buf[buf_nr]);

                            g_buf[buf_nr] = NULL;
                        }
                    }
                }
                break;

            case ARG_DATA_PRIVATE:
                free(g_tmp_buf[arg_nr]);

                g_tmp_buf[arg_nr] = NULL;
                break;
        }

        p_arg = (SYSCALL_ARG*)(((char*)p_arg) + arg_size(GET_ARG_TYPE(sys_invoke_p->arg_type, arg_nr)));
    }
}

TEE_Result do_payload(const void *buf, size_t buf_len) {
    CTX ctx = {
            .buf = buf,
            .buf_len = buf_len,

            .cmd_first = buf,
            .cmd_current = NULL,

            .data = buf,
            .data_len = buf_len,

            .p_error = NULL
    };

    uint32_t s_nr = 0;

    uint64_t ret_val;
    while (CMD_NEXT(&ctx) != NULL) {
        assert(s_nr < MAX_CALLS);

        pre_invoke_syscall(&ctx);
        invoke_syscall(&ctx, &ret_val);
        post_invoke_syscall(&ctx);

        if (ret_val != TEE_SUCCESS)
            break;

        g_ret_val[s_nr] = ret_val;

        s_nr++;
    }

    return ret_val;
}