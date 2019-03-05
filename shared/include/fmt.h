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

#include <tee_api_defines.h>

static inline const char* gp_format_return_code(unsigned int return_code) {
	static char buf[128];

	switch (return_code) {
		case TEE_SUCCESS: return "SUCCESS";
		case TEE_ERROR_CORRUPT_OBJECT: return "CORRUPT_OBJECT";
		case TEE_ERROR_CORRUPT_OBJECT_2: return "CORRUPT_OBJECT_2";
		case TEE_ERROR_STORAGE_NOT_AVAILABLE: return "STORAGE_NOT_AVAILABLE";
		case TEE_ERROR_STORAGE_NOT_AVAILABLE_2: return "STORAGE_NOT_AVAILABLE_2";
		case TEE_ERROR_GENERIC: return "GENERIC";
		case TEE_ERROR_ACCESS_DENIED: return "ACCESS_DENIED";
		case TEE_ERROR_CANCEL: return "CANCEL";
		case TEE_ERROR_ACCESS_CONFLICT: return "ACCESS_CONFLICT";
		case TEE_ERROR_EXCESS_DATA: return "EXCESS_DATA";
		case TEE_ERROR_BAD_FORMAT: return "BAD_FORMAT";
		case TEE_ERROR_BAD_PARAMETERS: return "BAD_PARAMETERS";
		case TEE_ERROR_BAD_STATE: return "BAD_STATE";
		case TEE_ERROR_ITEM_NOT_FOUND: return "ITEM_NOT_FOUND";
		case TEE_ERROR_NOT_IMPLEMENTED: return "NOT_IMPLEMENTED";
		case TEE_ERROR_NOT_SUPPORTED: return "NOT_SUPPORTED";
		case TEE_ERROR_NO_DATA: return "NO_DATA";
		case TEE_ERROR_OUT_OF_MEMORY: return "OUT_OF_MEMORY";
		case TEE_ERROR_BUSY: return "BUSY";
		case TEE_ERROR_COMMUNICATION: return "COMMUNICATION";
		case TEE_ERROR_SECURITY: return "SECURITY";
		case TEE_ERROR_SHORT_BUFFER: return "SHORT_BUFFER";
		case TEE_ERROR_EXTERNAL_CANCEL: return "EXTERNAL_CANCEL";
		case TEE_ERROR_OVERFLOW: return "OVERFLOW";
		case TEE_ERROR_TARGET_DEAD: return "TARGET_DEAD";
		case TEE_ERROR_STORAGE_NO_SPACE: return "STORAGE_NO_SPACE";
		case TEE_ERROR_MAC_INVALID: return "MAC_INVALID";
		case TEE_ERROR_SIGNATURE_INVALID: return "SIGNATURE_INVALID";
		case TEE_ERROR_TIME_NOT_SET: return "TIME_NOT_SET";
		case TEE_ERROR_TIME_NEEDS_RESET: return "TIME_NEEDS_RESET";
	}

	snprintf(buf, sizeof(buf), "%x", return_code);

	return buf;
}