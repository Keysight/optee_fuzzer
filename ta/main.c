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

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <utee_defines.h>
#include <utee_syscalls.h>

#include <afl_ta.h>

#include <afl-tee.h>
#include <tee_api_types.h>

void __cache_data();

char *strcpy(char *dest, const char *src) {
	char *save = dest;
	while((*dest++ = *src++));
	return save;
}

TEE_Result TA_CreateEntryPoint(void) {
	__cache_data();

	IMSG("Created SVC-Invoke TA");

	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx) {

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	IMSG("Created SVC-Invoke TA session");

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx) {
	(void)&sess_ctx; /* Unused parameter */
}

TEE_Result do_payload(const void* const buf, const size_t buf_len);

uint8_t* __afl_area_ptr;

#define CFG_AFL_PRINT_DURATION

static TEE_Result invoke_svc_cmd(uint32_t param_types, TEE_Param params[4])  {
	TEE_Result last_result;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
											   TEE_PARAM_TYPE_MEMREF_OUTPUT,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE);

#ifdef CFG_AFL_PRINT_DURATION
	TEE_Time time_start, time_end, time_duration;
	TEE_GetSystemTime(&time_start);
#endif

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	const uint8_t* const payload = params[0].memref.buffer;
	const size_t payload_len = params[0].memref.size;

#if 0
	size_t payload_len = params[0].memref.size;

	// validate
	char* p_err;
	if (!is_valid_cmd(payload, payload_len, &p_err)) {
		EMSG("Payload parsing failed: %s\n", p_err);

		return TEE_ERROR_BAD_PARAMETERS;
	}
#endif

	if (params[1].memref.size != (1<<16)) {
		EMSG("Incorrect map size");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	__afl_area_ptr = params[1].memref.buffer;
	size_t bitmap_len = params[1].memref.size;

	// init bitmap
	utee_afl_cov_bitmap_init(payload, payload_len);

	// invoke svc(s)
	last_result = do_payload(payload, payload_len);

	utee_afl_cov_bitmap_shutdown(__afl_area_ptr);

	__afl_area_ptr[0]++; // To make AFL happy

#ifdef CFG_AFL_PRINT_DURATION
	TEE_GetSystemTime(&time_end);

	TEE_TIME_SUB(time_end, time_start, time_duration);

	IMSG("R: %x (%lu ms)\n", last_result, (time_duration.seconds * 1000) + time_duration.millis);
#endif

	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
		case TA_AFL_CMD_INVOKE_SVC:
			return invoke_svc_cmd(param_types, params);
		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}
}
