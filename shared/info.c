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

#include <afl-tee.h>

#if defined(TA_BUILD)

#include <utee_types.h>
#include <tee_api_types.h>
#include <utee_syscalls.h>

#define DEF_SYSCALL(name, scn, num_args, ...) \
    { scn, num_args, #name, __VA_ARGS__, &utee_ ## name },

#elif defined(__KERNEL__)

#define DEF_SYSCALL(name, scn, num_args, ...) \
    { scn, num_args, #name, __VA_ARGS__ },

#else

#define DEF_SYSCALL(name, scn, num_args, ...) \
    { scn, num_args, #name }, 

#endif

SYSCALL_INFO syscalls[] = {
    DEF_SYSCALL(return, TEE_SCN_RETURN, 1, { ARG_VALUE })
    DEF_SYSCALL(log, TEE_SCN_LOG, 2, { ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(1), ARG_VALUE })
    DEF_SYSCALL(panic, TEE_SCN_PANIC, 2, { ARG_VALUE })
    DEF_SYSCALL(get_property, TEE_SCN_GET_PROPERTY, 7, { ARG_VALUE, ARG_VALUE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(3), ARG_VALUE_INOUT_PTR, ARG_VALUE_INOUT_PTR, ARG_VALUE, ARG_VALUE_OUT_PTR  })
    DEF_SYSCALL(get_property_name_to_index, TEE_SCN_GET_PROPERTY_NAME_TO_INDEX, 4, { ARG_VALUE, ARG_VALUE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(3), ARG_VALUE, ARG_VALUE_OUT_PTR  })
    DEF_SYSCALL(open_ta_session, TEE_SCN_OPEN_TA_SESSION, 5, { ARG_BUF_IN_ADDR | ARG_BUF_SIZE(sizeof(TEE_UUID)), ARG_VALUE, ARG_BUF_INOUT_ADDR | ARG_BUF_SIZE(sizeof(struct utee_params)), ARG_HANDLE_OUT_PTR, ARG_VALUE_OUT_PTR  })
    DEF_SYSCALL(close_ta_session, TEE_SCN_CLOSE_TA_SESSION, 1, { ARG_HANDLE })
    DEF_SYSCALL(invoke_ta_command, TEE_SCN_INVOKE_TA_COMMAND, 5, { ARG_HANDLE, ARG_VALUE, ARG_VALUE, ARG_BUF_INOUT_ADDR | ARG_BUF_SIZE(sizeof(struct utee_params)), ARG_VALUE_OUT_PTR })
    DEF_SYSCALL(get_cancellation_flag, TEE_SCN_GET_CANCELLATION_FLAG, 1, { ARG_VALUE_OUT_PTR })
    DEF_SYSCALL(check_access_rights, TEE_SCN_CHECK_ACCESS_RIGHTS, 3, { ARG_VALUE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(2), ARG_VALUE })
    DEF_SYSCALL(unmask_cancellation, TEE_SCN_UNMASK_CANCELLATION, 1, { ARG_VALUE_OUT_PTR })
    DEF_SYSCALL(mask_cancellation, TEE_SCN_MASK_CANCELLATION, 1, { ARG_VALUE_OUT_PTR })
    DEF_SYSCALL(wait, TEE_SCN_WAIT, 1, { ARG_VALUE })
    DEF_SYSCALL(get_time, TEE_SCN_GET_TIME, 2, { ARG_VALUE, ARG_BUF_OUT_ADDR | ARG_BUF_SIZE(sizeof(TEE_Time)) })
    DEF_SYSCALL(set_ta_time, TEE_SCN_SET_TA_TIME, 1, { ARG_BUF_IN_ADDR | ARG_BUF_SIZE(sizeof(TEE_Time)) })
    DEF_SYSCALL(cryp_state_alloc, TEE_SCN_CRYP_STATE_ALLOC, 5, { ARG_VALUE, ARG_VALUE, ARG_HANDLE, ARG_HANDLE, ARG_HANDLE_OUT_PTR })
    DEF_SYSCALL(cryp_state_copy, TEE_SCN_CRYP_STATE_COPY, 2, { ARG_HANDLE, ARG_HANDLE })
    DEF_SYSCALL(cryp_state_free, TEE_SCN_CRYP_STATE_FREE, 1, { ARG_HANDLE })
    DEF_SYSCALL(hash_init, TEE_SCN_HASH_INIT, 3, { ARG_HANDLE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(2), ARG_VALUE })
    DEF_SYSCALL(hash_update, TEE_SCN_HASH_UPDATE, 3, { ARG_HANDLE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(2), ARG_VALUE })
    DEF_SYSCALL(hash_final, TEE_SCN_HASH_FINAL, 5, { ARG_HANDLE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(2), ARG_VALUE, ARG_BUF_OUT_ADDR | ARG_BUF_LEN_ARG(4), ARG_VALUE_INOUT_PTR })
    DEF_SYSCALL(cipher_init, TEE_SCN_CIPHER_INIT, 3, { ARG_HANDLE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(2), ARG_VALUE })
    DEF_SYSCALL(cipher_update, TEE_SCN_CIPHER_UPDATE, 5, { ARG_HANDLE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(2), ARG_VALUE, ARG_BUF_OUT_ADDR | ARG_BUF_LEN_ARG(4), ARG_VALUE_INOUT_PTR })
    DEF_SYSCALL(cipher_final, TEE_SCN_CIPHER_FINAL, 5, { ARG_HANDLE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(2), ARG_VALUE, ARG_BUF_OUT_ADDR | ARG_BUF_LEN_ARG(4), ARG_VALUE_INOUT_PTR })
    DEF_SYSCALL(cryp_obj_get_info, TEE_SCN_CRYP_OBJ_GET_INFO, 2, { ARG_HANDLE, ARG_BUF_OUT_ADDR | ARG_BUF_SIZE(sizeof(TEE_ObjectInfo)) })
    DEF_SYSCALL(cryp_obj_restrict_usage, TEE_SCN_CRYP_OBJ_RESTRICT_USAGE, 2, { ARG_HANDLE, ARG_VALUE })
    DEF_SYSCALL(cryp_obj_get_attr, TEE_SCN_CRYP_OBJ_GET_ATTR, 4, { ARG_HANDLE, ARG_VALUE, ARG_BUF_OUT_ADDR | ARG_BUF_LEN_ARG(3), ARG_VALUE_INOUT_PTR })
    DEF_SYSCALL(cryp_obj_alloc, TEE_SCN_CRYP_OBJ_ALLOC, 3, { ARG_VALUE, ARG_VALUE, ARG_HANDLE_OUT_PTR })
    DEF_SYSCALL(cryp_obj_close, TEE_SCN_CRYP_OBJ_CLOSE, 1, { ARG_HANDLE })
    DEF_SYSCALL(cryp_obj_reset, TEE_SCN_CRYP_OBJ_RESET, 1, {ARG_HANDLE })
    DEF_SYSCALL(cryp_obj_populate, TEE_SCN_CRYP_OBJ_POPULATE, 3, { ARG_HANDLE, ARG_BUF_IN_ADDR | ARG_BUF_TYPE(ARG_TYPE_ATTR) | ARG_BUF_LEN_ARG(2) | ARG_BUF_SIZE(sizeof(struct utee_attribute)), ARG_VALUE })
    DEF_SYSCALL(cryp_obj_copy, TEE_SCN_CRYP_OBJ_COPY, 2, { ARG_HANDLE, ARG_HANDLE })
    DEF_SYSCALL(cryp_obj_generate_key, TEE_SCN_CRYP_OBJ_GENERATE_KEY, 4, { ARG_HANDLE, ARG_VALUE, ARG_BUF_IN_ADDR | ARG_BUF_TYPE(ARG_TYPE_ATTR) | ARG_BUF_LEN_ARG(3) | ARG_BUF_SIZE(sizeof(struct utee_attribute)), ARG_VALUE })
    DEF_SYSCALL(cryp_derive_key, TEE_SCN_CRYP_DERIVE_KEY, 4, { ARG_HANDLE, ARG_BUF_IN_ADDR | ARG_BUF_TYPE(ARG_TYPE_ATTR) | ARG_BUF_LEN_ARG(2) | ARG_BUF_SIZE(sizeof(struct utee_attribute)), ARG_VALUE, ARG_HANDLE })
    DEF_SYSCALL(cryp_random_number_generate, TEE_SCN_CRYP_RANDOM_NUMBER_GENERATE, 2, { ARG_BUF_OUT_ADDR | ARG_BUF_LEN_ARG(1), ARG_VALUE })
    DEF_SYSCALL(authenc_init, TEE_SCN_AUTHENC_INIT, 6, { ARG_HANDLE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(2), ARG_VALUE, ARG_VALUE, ARG_VALUE, ARG_VALUE })
    DEF_SYSCALL(authenc_update_aad, TEE_SCN_AUTHENC_UPDATE_AAD, 3, { ARG_HANDLE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(2), ARG_VALUE })
    DEF_SYSCALL(authenc_update_payload, TEE_SCN_AUTHENC_UPDATE_PAYLOAD, 5, { ARG_HANDLE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(2), ARG_VALUE, ARG_BUF_OUT_ADDR | ARG_BUF_LEN_ARG(4), ARG_VALUE_INOUT_PTR })
    DEF_SYSCALL(authenc_enc_final, TEE_SCN_AUTHENC_ENC_FINAL, 7, { ARG_HANDLE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(2), ARG_VALUE, ARG_BUF_OUT_ADDR | ARG_BUF_LEN_ARG(4), ARG_VALUE_INOUT_PTR, ARG_BUF_OUT_ADDR | ARG_BUF_LEN_ARG(6), ARG_VALUE_INOUT_PTR })
    DEF_SYSCALL(authenc_dec_final, TEE_SCN_AUTHENC_DEC_FINAL, 7, { ARG_HANDLE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(2), ARG_VALUE, ARG_BUF_OUT_ADDR | ARG_BUF_LEN_ARG(4), ARG_VALUE_INOUT_PTR, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(6), ARG_VALUE })
    DEF_SYSCALL(asymm_operate, TEE_SCN_ASYMM_OPERATE, 7, { ARG_HANDLE, ARG_BUF_IN_ADDR | ARG_BUF_TYPE(ARG_TYPE_ATTR) | ARG_BUF_LEN_ARG(2) | ARG_BUF_SIZE(sizeof(struct utee_attribute)), ARG_VALUE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(4), ARG_VALUE, ARG_BUF_OUT_ADDR | ARG_BUF_LEN_ARG(6), ARG_VALUE_INOUT_PTR })
    DEF_SYSCALL(asymm_verify, TEE_SCN_ASYMM_VERIFY, 7, { ARG_HANDLE, ARG_BUF_IN_ADDR | ARG_BUF_TYPE(ARG_TYPE_ATTR) | ARG_BUF_LEN_ARG(2) | ARG_BUF_SIZE(sizeof(struct utee_attribute)), ARG_VALUE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(4), ARG_VALUE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(6), ARG_VALUE })
    DEF_SYSCALL(storage_obj_open, TEE_SCN_STORAGE_OBJ_OPEN, 5, { ARG_VALUE, ARG_BUF_IN_ADDR, ARG_VALUE, ARG_VALUE, ARG_HANDLE_OUT_PTR })
    DEF_SYSCALL(storage_obj_create, TEE_SCN_STORAGE_OBJ_CREATE, 8, { ARG_VALUE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(2), ARG_VALUE, ARG_VALUE, ARG_VALUE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(6), ARG_VALUE, ARG_HANDLE_OUT_PTR })
    DEF_SYSCALL(storage_obj_del, TEE_SCN_STORAGE_OBJ_DEL, 1, { ARG_HANDLE })
    DEF_SYSCALL(storage_obj_rename, TEE_SCN_STORAGE_OBJ_RENAME, 3, { ARG_HANDLE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(2), ARG_VALUE })
    DEF_SYSCALL(storage_alloc_enum, TEE_SCN_STORAGE_ENUM_ALLOC, 1, { ARG_HANDLE_OUT_PTR })
    DEF_SYSCALL(storage_free_enum, TEE_SCN_STORAGE_ENUM_FREE, 1, { ARG_HANDLE })
    DEF_SYSCALL(storage_reset_enum, TEE_SCN_STORAGE_ENUM_RESET, 1, { ARG_HANDLE })
    DEF_SYSCALL(storage_start_enum, TEE_SCN_STORAGE_ENUM_START, 2, { ARG_HANDLE, ARG_VALUE })
    DEF_SYSCALL(storage_next_enum, TEE_SCN_STORAGE_ENUM_NEXT, 4, { ARG_HANDLE, ARG_BUF_OUT_ADDR | ARG_BUF_SIZE(sizeof(TEE_ObjectInfo)), ARG_HANDLE_OUT_PTR, ARG_VALUE_OUT_PTR })
    DEF_SYSCALL(storage_obj_read, TEE_SCN_STORAGE_OBJ_READ, 4, { ARG_HANDLE, ARG_BUF_OUT_ADDR | ARG_BUF_LEN_ARG(2), ARG_VALUE, ARG_VALUE_OUT_PTR })
    DEF_SYSCALL(storage_obj_write, TEE_SCN_STORAGE_OBJ_WRITE, 3, { ARG_HANDLE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(2), ARG_VALUE })
    DEF_SYSCALL(storage_obj_trunc, TEE_SCN_STORAGE_OBJ_TRUNC, 2, { ARG_HANDLE, ARG_VALUE })
    DEF_SYSCALL(storage_obj_seek, TEE_SCN_STORAGE_OBJ_SEEK, 3, { ARG_HANDLE, ARG_VALUE, ARG_VALUE })
    DEF_SYSCALL(se_service_open, TEE_SCN_SE_SERVICE_OPEN, 1, { ARG_HANDLE_OUT_PTR })
    DEF_SYSCALL(se_service_close, TEE_SCN_SE_SERVICE_CLOSE, 1, { ARG_HANDLE })
    DEF_SYSCALL(se_service_get_readers, TEE_SCN_SE_SERVICE_GET_READERS, 3, { ARG_HANDLE, ARG_BUF_OUT_ADDR | ARG_BUF_LEN_ARG(2), ARG_VALUE_INOUT_PTR })
    DEF_SYSCALL(se_reader_get_prop, TEE_SCN_SE_READER_GET_PROP, 2, { ARG_HANDLE, ARG_VALUE_OUT_PTR })
    DEF_SYSCALL(se_reader_get_name, TEE_SCN_SE_READER_GET_NAME, 3, { ARG_HANDLE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(2), ARG_VALUE_INOUT_PTR })
    DEF_SYSCALL(se_reader_open_session, TEE_SCN_SE_READER_OPEN_SESSION, 2, { ARG_HANDLE, ARG_HANDLE_OUT_PTR })
    DEF_SYSCALL(se_reader_close_sessions, TEE_SCN_SE_READER_CLOSE_SESSIONS, 1, { ARG_HANDLE })
    DEF_SYSCALL(se_session_is_closed, TEE_SCN_SE_SESSION_IS_CLOSED, 1, { ARG_HANDLE })
    DEF_SYSCALL(se_session_get_atr, TEE_SCN_SE_SESSION_GET_ATR, 3, { ARG_HANDLE, ARG_BUF_OUT_ADDR | ARG_BUF_LEN_ARG(2), ARG_VALUE_INOUT_PTR })
    DEF_SYSCALL(se_session_open_channel, TEE_SCN_SE_SESSION_OPEN_CHANNEL, 5, { ARG_HANDLE, ARG_VALUE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(3), ARG_VALUE, ARG_HANDLE_OUT_PTR })
    DEF_SYSCALL(se_session_close, TEE_SCN_SE_SESSION_CLOSE, 1, { ARG_HANDLE })
    DEF_SYSCALL(se_channel_select_next, TEE_SCN_SE_CHANNEL_SELECT_NEXT, 1, { ARG_HANDLE })
    DEF_SYSCALL(se_channel_get_select_resp, TEE_SCN_SE_CHANNEL_GET_SELECT_RESP, 3, { ARG_HANDLE, ARG_BUF_OUT_ADDR | ARG_BUF_LEN_ARG(2), ARG_VALUE_INOUT_PTR })
    DEF_SYSCALL(se_channel_transmit, TEE_SCN_SE_CHANNEL_TRANSMIT, 5, { ARG_HANDLE, ARG_BUF_IN_ADDR | ARG_BUF_LEN_ARG(2), ARG_VALUE, ARG_BUF_OUT_ADDR | ARG_BUF_LEN_ARG(4), ARG_VALUE_INOUT_PTR })
    DEF_SYSCALL(se_channel_close, TEE_SCN_SE_CHANNEL_CLOSE, 1, { ARG_HANDLE })
    DEF_SYSCALL(cache_operation, TEE_SCN_CACHE_OPERATION, 3, { ARG_VALUE, ARG_VALUE, ARG_VALUE })
};


const char* __gi_name[TEE_SCN_MAX+1];
uint32_t __gi_args[TEE_SCN_MAX+1];

#ifdef TA_BUILD
const void* __gi_fptr[TEE_SCN_MAX+1];
#endif

static uint64_t syscall_arg_info(uint32_t nr, uint32_t arg_nr) {
    for (uint32_t i = 0; i <= TEE_SCN_MAX; i++) {
        if (syscalls[i].nr == nr) {
            assert(arg_nr < TEE_SVC_MAX_ARGS);

            if (syscalls[i].arg_info[arg_nr] == 0) {
                EMSG("Argument %x info missing for scn %x", arg_nr, nr);
                assert(0);
            }

            return syscalls[i].arg_info[arg_nr];
        }
    }

    assert(0);
}

__attribute__((constructor))
void __cache_data() {
    for (uint32_t i = 0; i <= TEE_SCN_MAX; i++) {
        __gi_name[syscalls[i].nr] = syscalls[i].name;
        __gi_args[syscalls[i].nr] = syscalls[i].num_args;
#ifdef TA_BUILD
        __gi_fptr[syscalls[i].nr] = syscalls[i].fptr;
#endif
    }
}
