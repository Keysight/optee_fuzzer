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

static bool allocates_buffer(const SYSCALL_INVOKE* syscall, uint32_t buf_nr) {
    SVC_FOREACH_ARG_UNTIL_VAL_NONE(syscall, p_arg, arg_type, {
        switch (arg_type) {
            case ARG_BUFFER_ALLOC:
                if (buf_nr == p_arg->buffer.nr) {
                    return true;
                }
                break;

            default:
                break;
        }
    });

    return false;
}

static bool uses_buffer(const SYSCALL_INVOKE* syscall, uint32_t buf_nr) {
    SVC_FOREACH_ARG_UNTIL_VAL_NONE(syscall, p_arg, arg_type, {
        switch (arg_type) {
            case ARG_BUFFER_ALLOC:
            case ARG_BUFFER_REF:
            case ARG_BUFFER_DEREF32:
            case ARG_BUFFER_DEREF64:
                if (buf_nr == p_arg->buffer.nr) {
                    return true;
                }
                break;

            default:
                break;
        }
    });

    return false;
}

bool is_buffer_used_after(CTX_CP ctx, uint32_t buf_nr) {
    CMD_CTX_CLONE(ctx, ctx_new);

    const SYSCALL_INVOKE* sys_invoke_p;

    while ((sys_invoke_p = CMD_NEXT(&ctx_new)) != NULL) {
        if (uses_buffer(sys_invoke_p, buf_nr)) {
            return true;
        }
    }

    return false;
}

static bool is_buffer_allocated(CTX_CP ctx, uint32_t buf_nr) {
    CMD_CTX_CLONE(ctx, ctx_new);

    CMD_RESET_CURRENT(&ctx_new);

    const SYSCALL_INVOKE* sys_invoke_p;

    while ((sys_invoke_p = CMD_NEXT(&ctx_new)) != NULL) {
        if (sys_invoke_p == CMD_CURRENT(ctx))
            return false;

        if (allocates_buffer(sys_invoke_p, buf_nr)) {
            return true;
        }
    }

    return false;
}

static bool is_valid_invoke_arg(CTX_CP ctx, uint32_t s_nr, SYSCALL_ARG_TYPE arg_type, const SYSCALL_ARG* const arg) {
    switch (arg_type) {
        case ARG_VALUE_8:
        case ARG_VALUE_16:
        case ARG_VALUE_32:
        case ARG_VALUE_64:
        case ARG_VALUE_NULL:
            break;

        case ARG_RETURN_VALUE:
            if (arg->ret_val >= s_nr) {
                CMD_ERR(ctx, "Referenced return value has to be before current call");

                return false;
            }
            break;

        case ARG_BUFFER_ALLOC:
            if (arg->buffer.nr >= MAX_BUF_COUNT) {
                CMD_ERR(ctx, "Buffer number above maximum number of buffers");

                return false;
            }

            if (is_buffer_allocated(ctx, arg->buffer.nr)) {
                CMD_ERR(ctx, "Buffer %x already allocated", arg->buffer.nr);

                return false;
            }

            if (arg->buffer.len == 0) {
                CMD_ERR(ctx, "Buffer length = 0");

                return false;
            }

            if (arg->buffer.len > 2*1024) {
                CMD_ERR(ctx, "Buffer length > 2KiB");

                return false;
            }

            break;

        case ARG_BUFFER_REF:
        case ARG_BUFFER_DEREF32:
        case ARG_BUFFER_DEREF64:
            if (arg->buffer.nr >= MAX_BUF_COUNT) {
                CMD_ERR(ctx, "Buffer number above maximum number of buffers");

                return false;
            }

            if (!is_buffer_allocated(ctx, arg->buffer.nr)) {
                CMD_ERR(ctx, "Buffer %x not allocated", arg->buffer.nr);

                return false;
            }
            break;

        case ARG_DATA_SHARED:
        case ARG_DATA_PRIVATE:
            if ((uint32_t)arg->data.offset >= ctx->data_len) {
                CMD_ERR(ctx, "Data offset (%x) not within boundaries (%x)", (uint32_t)arg->data.offset, ctx->data_len);

                return false;
            }

            if ((uint32_t)arg->data.offset >= ctx->data_len) {
                CMD_ERR(ctx, "Data length (%x) not within boundaries (%x)", (uint32_t)arg->data.offset, ctx->data_len);

                return false;
            }

            if (arg->data.len == 0) {
                CMD_ERR(ctx, "Data length = 0");

                return false;
            }

            if (arg->data.len > 2*1024) {
                CMD_ERR(ctx, "Data length (%x) > 2KiB", arg->data.len);

                return false;
            }
            break;

        case ARG_TEE_ATTR:
            if ((uint32_t)arg->tee_attr.offset >= ctx->data_len || (uint32_t)arg->tee_attr.offset + arg->tee_attr.len > ctx->data_len) {
                CMD_ERR(ctx, "TEE Attr data offset or length not within boundaries");

                return false;
            }

            if (arg->tee_attr.len == 0) {
                CMD_ERR(ctx, "TEE Attr data length = 0");

                return false;
            }

            if (arg->tee_attr.len > 2*1024) {
                CMD_ERR(ctx, "TEE Attr data length (%x) > 2KiB", arg->data.len);

                return false;
            }
            break;

        default:
            assert(false);
    }

    return true;
}

static bool is_valid_invoke(CTX_CP ctx, uint32_t s_nr) {
    const SYSCALL_INVOKE* const sys_invoke_p = CMD_CURRENT(ctx);

    // Valid cmd?
    if (sys_invoke_p->nr > TEE_SCN_MAX) {
        CMD_ERR(ctx, "Unknown syscall %i", sys_invoke_p->nr);

        return false;
    }

    // Check padding (Note: this rejects many test cases)
    //if (sys_invoke_p->__pad[0] || sys_invoke_p->__pad[1] || sys_invoke_p->__pad[2]) {
    //    CMD_ERR(ctx, "Invalid padding");
    //
    //    return false;
    //}

    if (syscall_must_skip(sys_invoke_p->nr)) {
        CMD_ERR(ctx, "Must skip syscall 0x%x", sys_invoke_p->nr);

        return false;
    }

    uint32_t num_args = 0;

    // Valid Args
    SVC_FOREACH_ARG(sys_invoke_p, 0, syscall_num_args(sys_invoke_p->nr), p_arg, arg_type, {
        switch (arg_type) {
            case ARG_NONE:
                if (num_args < syscall_num_args(sys_invoke_p->nr)) {
                    CMD_ERR(ctx, "Required argument %x missing", arg_nr);

                    return false;
                }

            case ARG_VALUE_NULL:
            case ARG_VALUE_8:
            case ARG_VALUE_16:
            case ARG_VALUE_32:
            case ARG_VALUE_64:
            case ARG_RETURN_VALUE:
            case ARG_BUFFER_ALLOC:
            case ARG_BUFFER_REF:
            case ARG_BUFFER_DEREF32:
            case ARG_BUFFER_DEREF64:
            case ARG_DATA_SHARED:
            case ARG_DATA_PRIVATE:
            case ARG_TEE_ATTR:
                /*
                // After a none arg we cannot have normal args
                if (had_none) {
                    CMD_ERR(ctx, "Argument missing between 2 arguments");

                    return false;
                }
                */

                if (!is_valid_invoke_arg(ctx, s_nr, GET_ARG_TYPE(sys_invoke_p->arg_type, arg_nr), p_arg)) {
                    return false;
                }

                num_args++;
                break;

            default:
                CMD_ERR(ctx, "Unexpected argument type");

                return false;
        }
    });

    // Enfore the correct number of arguments
    // Note that this is difficult to bruteforce through if we have no test cases with the correct amount of arguments
    //if (num_args != syscall_num_args(sys_invoke_p->nr)) {
    //    CMD_ERR(ctx, "Invalid amount of arguments");
    //
    //    return false;
    //}

    return true;
}

bool is_valid_cmd_buf(const void *buf, size_t buf_len, char **p_error) {
    CTX ctx = {
            .buf = buf,
            .buf_len = buf_len,

            .cmd_first = buf,
            .cmd_current = NULL,

            .data = buf,
            .data_len = buf_len,

            .p_error = p_error
    };

    // Minimum size
    if (buf_len < sizeof(SYSCALL_INVOKE)) {
        CMD_ERR(&ctx, "Payload less than minimum size");

        return false;
    }

    uint32_t syscn = 0;
    while (CMD_NEXT(&ctx) != NULL) {
        if (syscn >= MAX_CALLS) {
            CMD_ERR(&ctx, "More calls than supported");

            return false;
        }

        if (!is_valid_invoke(&ctx, syscn)) {
            return false;
        }

        syscn++;
    }

    if (!syscn) {
        CMD_ERR(&ctx, "No calls");

        return false;
    }

    return true;
}