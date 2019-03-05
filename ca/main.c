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

#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <tee_client_api.h>

#include <afl-tee.h>
#include <afl_ta.h>

#include "rt.h"

void init_ta(TEEC_Context* ctx, TEEC_Session* sess) {
    TEEC_Result res;
    TEEC_UUID uuid = TA_AFL_UUID;
    uint32_t err_origin;

    res = TEEC_InitializeContext(NULL, ctx);

    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
        abort();
    }

    res = TEEC_OpenSession(ctx, sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);
        abort();
    }
}

void shutdown_ta(TEEC_Context* ctx, TEEC_Session* sess) {
    TEEC_CloseSession(sess);

    TEEC_FinalizeContext(ctx);
}

void do_cmd_invoke_svc(TEEC_Context* ctx, TEEC_Session* sess, void* buf, size_t buf_len, void* map, size_t map_size) {
    TEEC_Result res;
    TEEC_Operation op;

    uint32_t err_origin;

    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = buf;
    op.params[0].tmpref.size = buf_len;

    op.params[1].tmpref.buffer = map;
    op.params[1].tmpref.size = map_size;

    res = TEEC_InvokeCommand(sess, TA_AFL_CMD_INVOKE_SVC, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        TEEC_CloseSession(sess);
        TEEC_FinalizeContext(ctx);

        printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
        abort();
    }
}

#define BUF_SIZE (16*1024)

int main(int argc, char *argv[]) {
    TEEC_Context ctx;
    TEEC_Session sess;

    bool readStdin = __afl_area_ptr != NULL;

    if (argc <= 1 && !readStdin) {
        printf("%s <payload>\n", argv[0]);
        exit(-1);
    }

    if (!readStdin)
        __afl_area_ptr = malloc(MAP_SIZE);

    // invoke TA
    init_ta(&ctx, &sess);        

    if (readStdin) {
        char *buf = malloc(BUF_SIZE);
        size_t buf_len;

        while (__AFL_LOOP(1000)) {
            // to keep AFL happy
            __afl_area_ptr[MAP_SIZE - 1] = 1;

            buf_len = read(0, buf, BUF_SIZE);
            memset(buf + buf_len, 0, BUF_SIZE - buf_len);

            //char *p_err = "unknown error";
            //if (!is_valid_cmd_buf(buf, buf_len, &p_err)) {
            //    printf("Payload parsing failed: %s\n", p_err);
            //    exit(-1);
            //}

            do_cmd_invoke_svc(&ctx, &sess, buf, buf_len, __afl_area_ptr, MAP_SIZE);
        }
    }
    else {
        FILE *f = fopen(argv[1], "rb");

        if (!f) {
            printf("File not found: %s\n", argv[1]);
            exit(-1);
        }

        fseek(f, 0, SEEK_END);
        long buf_len = ftell(f);
        fseek(f, 0, SEEK_SET);

        char *buf = malloc(buf_len);
        fread(buf, buf_len, 1, f);
        fclose(f);

        char *p_err = "unknown error";
        if (!is_valid_cmd_buf(buf, (size_t) buf_len, &p_err)) {
            printf("Payload parsing failed: %s\n", p_err);
            exit(-1);
        }

        do_cmd_invoke_svc(&ctx, &sess, buf, (size_t)buf_len, __afl_area_ptr, MAP_SIZE);
    }

    shutdown_ta(&ctx, &sess);

    return 0;
}