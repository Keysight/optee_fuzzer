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

#include <stdint.h>

static inline const uint8_t* beautify_data(const uint8_t* data, size_t len) {
    static uint8_t buf[128] = {0};

    size_t off = 0;

    if (len > 32) {
        off += snprintf(&buf[off], sizeof(buf) - off, "\"...\"");
    }
    else {
        off += snprintf(&buf[off], sizeof(buf) - off, "\"");

        for (uint32_t i = 0; i < len; i++) {
            if (data[i] >= ' ' && data[i] <= '~') {
                off += snprintf(&buf[off], sizeof(buf) - off, "%c", data[i]);
            }
            else {
                off += snprintf(&buf[off], sizeof(buf) - off, "\\x%02x", data[i]);
            }
        }

        off += snprintf(&buf[off], sizeof(buf) - off, "\"");

        // overflow !?!
        if (off >= sizeof(buf))
            abort();
    }

    return buf;
}