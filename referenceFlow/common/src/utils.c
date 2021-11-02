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

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

int verbose = 0;

size_t address_bits_required(uint64_t addr) {
    size_t length = 64;
    size_t sign;
    size_t sign_bit = (addr >> (length - 1)) & 1U;
    --length;
    do {
        sign = (addr >> (length - 1)) & 1U;
        --length;
    } while ((sign_bit == sign) && (length > 0));

    if (sign_bit == sign)
        return 1;
    else
        return length + 2;
}

/* This is the length of the message as sent by the message engine.
There sign-extension based compression built into
the UltraSoc message system. If the upper N bytes of the message are all the
same value as the MSB of the next byte, then the message length is
reduced by N before it is sent.  The software decoding the message
knows from the message type how long it should be, so if it receives a
message shorter than this, it recovers the missing bytes by sign
extending.
Note: the final (and most-significant) byte may have fewer than
eight valid bits ... hence we need to be careful to mask out any
invalid bits when processing this final byte. */
size_t message_bytes_required(
    const uint8_t * const msg,
    const size_t num_bits)
{
    /* total rounded up length (in bytes) */
    size_t length = (num_bits + 7u) >> 3;

    if (length <= 1u)   /* only zero or one byte anyway ? */
    {
        return length;  /* uncompressable ... return full length */
    }

    /* number of valid bits in last (MSB) byte [1,8] */
    const size_t num_final_bits = ((num_bits - 1u) & 7u) + 1u;

    /* mask for all the valid bits in the last byte */
    const uint8_t valid_mask = (1u << num_final_bits) - 1u;
    /* mask for all the invalid bits in the last byte */
    __attribute__((unused))
    const uint8_t invalid_mask = ~valid_mask;

    assert(msg);

    /* value of the final (i.e. most-significant) byte */
    const uint8_t final_byte = msg[length - 1u];
    /* value of the final (i.e. most-significant) bit */
    const uint8_t final_bit = final_byte & 1u;
    /* sign-extended byte, using the final bit */
    const uint8_t sign_ext_byte = final_bit ? 0xffu : 0x00u;

    /* check all the invalid bits are actually zero! */
    assert( !(final_byte & invalid_mask) );

    /*
     * If all the valid bits are either all zeros, or are all ones,
     * then we may be able to compress this bit-stream by sign-extending ...
     * otherwise we return the unexpurgated length now.
     */
    if ( ((final_byte & valid_mask) != 0) &&
         ((final_byte & valid_mask) != valid_mask) )
    {
        return length;  /* uncompressable ... return full length */
    }

    /* look at the penultimate byte next */
    length -= 2;

    while ( (length > 0u) && (sign_ext_byte == msg[length]) )
    {
        --length;
    }

    /* extract the most-significant bit of the previous byte */
    const size_t sign_bit = (msg[length] >> 7) & 1u;

    /* is it the same as all the other more significant bits */
    if (sign_bit == final_bit)
    {
        return length + 1u;
    }
    else
    {
        return length + 2u;
    }
}

/* Need to store the last address sent so that it can be used to
 calculate differential addresses */
static uint64_t last_address = UINT64_MAX;
static bool last_address_set = false;

bool has_last_address_set(void) {
    return last_address_set;
}

void set_last_address(uint64_t addr) {
    log_printf("  Set last_address 0x%lx\n", addr);
    last_address = addr;
    last_address_set = true;
}

uint64_t get_last_address() {
    return last_address;
}

uint64_t differential_address(uint64_t addr) {
    assert(has_last_address_set());
    return (addr - get_last_address());
}

uint32_t bool_array_to_uint32(const bool *array, uint8_t len) {
    uint32_t value = 0;

    // len == 0 is now a special case meaning 31 bits
    if (len == 0)
        len = 31;
    assert(len < 32);
    for (size_t i = 0; i < len; ++i) {
        if (array[i])
            value |= (1U << i);
    }

    return value;
}

void uint32_to_bool_array(uint32_t map, uint8_t len, bool *array) {
    // len == 0 is now a special case meaning 31 bits
    if (len == 0)
        len = 31;
    assert(len < 32);

    for (size_t i = 0; i < len; ++i)
        array[i] = ((map >> i & 1U) == 1U);
}

uint8_t get_bits(uint8_t data, size_t lsb, size_t nbits) {
    size_t msb = lsb + nbits - 1;
    assert(msb >= lsb);
    assert(msb < 8);
    uint8_t mask = ((0xff << lsb) & (0xff >> (7 - msb)));
    return ((data & mask) >> lsb);
}

void set_bits(uint8_t *data, size_t lsb, size_t nbits, uint8_t value) {
    *data |= (get_bits(value, 0, nbits) << lsb);
}

void log_printf(const char *format, ...) {
    va_list args;
    va_start(args, format);

    if (verbose) {
        vprintf(format, args);
#if defined(DEBUG)
        fflush(stdout);
#endif  /* DEBUG */
    }

    va_end(args);
}

uint32_t strtouint32(const char *nptr, int *parse_error) {
    assert(nptr != NULL);
    char *endptr = NULL;
    uint32_t value = strtoul(nptr, &endptr, 0);
    *parse_error = (*endptr != '\0');
    return value;
}

bool strtobool(const char *nptr, int *parse_error) {
    assert(nptr != NULL);
    *parse_error = 0;
    if (strcmp(nptr, "true") == 0 || strcmp(nptr, "t") == 0 || strcmp(nptr, "1") == 0)
        return true;
    if (strcmp(nptr, "false") == 0 || strcmp(nptr, "f") == 0 || strcmp(nptr, "0") == 0)
        return false;
    *parse_error = 1;
    return false;
}

char *create_filename(const char *stem, const char *ext) {
    assert(stem);
    assert(ext);
    size_t length = strlen(stem) + strlen(ext) + 1;
    char *result = malloc(length);
    assert(result != NULL);
    *result = '\0';
    strcat(result, stem);
    strcat(result, ext);
    return result;
}
