/*
 * SPDX-License-Identifier: BSD-2-Clause
 * SPDX-FileCopyrightText: Copyright 2019-2021 Siemens. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

extern int verbose;

size_t address_bits_required(uint64_t addr);
size_t message_bytes_required(
    const uint8_t * const msg,
    const size_t num_bits);     /* warning: previously was in bytes! */
bool has_last_address_set(void);
void set_last_address(uint64_t addr);
uint64_t get_last_address();
uint64_t differential_address(uint64_t addr);
uint32_t bool_array_to_uint32(const bool *array, uint8_t len);
void uint32_to_bool_array(uint32_t map, uint8_t len, bool *array);
uint8_t get_bits(uint8_t data, size_t lsb, size_t nbits);
void set_bits(uint8_t *data, size_t lsb, size_t nbits, uint8_t value);
void log_printf(const char *format, ...) __attribute__ ((format (printf, 1, 2)));
uint32_t strtouint32(const char *nptr, int *parse_error);
bool strtobool(const char *nptr, int *parse_error);
char *create_filename(const char *stem, const char *ext);
