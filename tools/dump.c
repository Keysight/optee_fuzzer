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

#include <stdio.h>
#include <assert.h>

#include <afl-tee.h>
#include <tee_api_defines.h>

bool g_buf[MAX_BUF_COUNT] = {0};

void dump_invoke_syscall(CTX_CP ctx, uint32_t s_nr) {
    const SYSCALL_INVOKE* const sys_invoke_p = CMD_CURRENT(ctx);

    printf("r[%i] = %s[%i](", s_nr, syscall_name(sys_invoke_p->nr), sys_invoke_p->nr);

    const SYSCALL_ARG* p_arg = &sys_invoke_p->args[0];

    bool first = true;
    for (uint32_t arg_nr = 0; arg_nr < syscall_num_args(sys_invoke_p->nr); arg_nr++) {
        SYSCALL_ARG_TYPE arg_type = GET_ARG_TYPE(sys_invoke_p->arg_type, arg_nr);

        assert(arg_type != ARG_NONE);

        if (!first) {
            printf(", ");
        }

        switch (arg_type) {
            case ARG_VALUE_NULL:
                printf("0x0");
                break;

            case ARG_VALUE_8:
                printf("0x%x", p_arg->val8);
                break;

            case ARG_VALUE_16:
                printf("0x%x", p_arg->val16);
                break;

            case ARG_VALUE_32:
                printf("0x%x", p_arg->val32);
                break;

            case ARG_VALUE_64:
                printf("0x%x", (uint32_t) p_arg->val64);
                break;

            case ARG_RETURN_VALUE:
                printf("r[%i]", p_arg->ret_val);
                break;

            case ARG_BUFFER_ALLOC:
            case ARG_BUFFER_REF:
                printf("b[%i]", p_arg->buffer.nr);
                break;

            case ARG_BUFFER_DEREF32:
                printf("*((uint32_t*)b[%i])", p_arg->buffer.nr);
                break;

            case ARG_BUFFER_DEREF64:
                printf("*((uint32_t*)b[%i])", p_arg->buffer.nr);
                break;

            case ARG_DATA_SHARED:
                printf("%s", beautify_data(CMD_DATA_PTR(ctx, p_arg->data.offset), p_arg->data.len));
                break;

            case ARG_DATA_PRIVATE:
                printf("t[%i]", arg_nr);
                break;

            case ARG_TEE_ATTR:
                printf("{%x, %s}", p_arg->tee_attr.attr, beautify_data(CMD_DATA_PTR(ctx, p_arg->tee_attr.offset), p_arg->tee_attr.len));
                break;
        }

        p_arg = (SYSCALL_ARG*)(((char*)p_arg) + arg_size(GET_ARG_TYPE(sys_invoke_p->arg_type, arg_nr)));

        first = false;
    }

    printf(");\n");
}

void dump_pre_invoke_syscall(CTX_CP ctx) {
    const SYSCALL_INVOKE* const sys_invoke_p = CMD_CURRENT(ctx);

    const SYSCALL_ARG* p_arg = &sys_invoke_p->args[0];

    for (uint32_t arg_nr = 0; arg_nr < syscall_num_args(sys_invoke_p->nr); arg_nr++) {
        SYSCALL_ARG_TYPE arg_type = GET_ARG_TYPE(sys_invoke_p->arg_type, arg_nr);

        assert(arg_type != ARG_NONE);

        switch (arg_type) {
            case ARG_BUFFER_ALLOC:
                if (!g_buf[p_arg->buffer.nr]) {
                    printf("b[%i] = malloc(%i);\n", p_arg->buffer.nr, p_arg->buffer.len);

                    g_buf[p_arg->buffer.nr] = true;
                }
                break;

            case ARG_DATA_PRIVATE:
                printf("t[%i] = malloc(%i);\n", arg_nr, p_arg->data.len);
                printf("memcpy(t[%i], %s, %i);\n", arg_nr, beautify_data(CMD_DATA_PTR(ctx, p_arg->data.offset), p_arg->data.len), p_arg->data.len);
                break;
        }

        p_arg = (SYSCALL_ARG*)(((char*)p_arg) + arg_size(arg_type));
    }
}

void dump_post_invoke_syscall(CTX_CP ctx) {
    const SYSCALL_INVOKE* const sys_invoke_p = CMD_CURRENT(ctx);

    const SYSCALL_ARG* p_arg = &sys_invoke_p->args[0];

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
                            printf("free(b[%i]);\n", buf_nr);
                        }
                    }
                }
                break;

            case ARG_DATA_PRIVATE:
                printf("free(t[%i]);\n", arg_nr);
                break;
        }

        p_arg = (SYSCALL_ARG*)(((char*)p_arg) + arg_size(arg_type));
    }
}

void dump_payload(const void *buf, size_t buf_len) {
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

    while (CMD_NEXT(&ctx) != NULL) {
        s_nr++;
    }

    printf("Calls: %i\n\n", s_nr);

    CMD_RESET_CURRENT(&ctx);

    s_nr = 0;

    while (CMD_NEXT(&ctx) != NULL) {
        dump_pre_invoke_syscall(&ctx);
        dump_invoke_syscall(&ctx, s_nr);
        dump_post_invoke_syscall(&ctx);

        s_nr++;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("%s <payload>\n", argv[0]);
        exit(-1);
    }

    FILE *f = fopen(argv[1], "rb");
    fseek(f, 0, SEEK_END);
    long buf_len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = malloc(buf_len);
    fread(buf, buf_len, 1, f);
    fclose(f);

    char* p_err = "unknown error";
    if (!is_valid_cmd_buf(buf, (size_t) buf_len, &p_err)) {
        printf("Payload parsing failed: %s\n", p_err);
        exit(-1);
    }

    dump_payload(buf, (size_t) buf_len);
    exit(0);
}