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

#include "unity.h"
#include "utils.h"

#define TE_MAX_NUM_BRANCHES 31u

void setUp(void) {
}

void tearDown(void) {
}

static void test_address_bits_required(void) {
    TEST_ASSERT_EQUAL(2, address_bits_required(0x1));
    TEST_ASSERT_EQUAL(3, address_bits_required(0x2));
    TEST_ASSERT_EQUAL(3, address_bits_required(0x3));
    TEST_ASSERT_EQUAL(15, address_bits_required(0x3543));
    TEST_ASSERT_EQUAL(16, address_bits_required(0x7fff));
    TEST_ASSERT_EQUAL(17, address_bits_required(0x8000));
    TEST_ASSERT_EQUAL(24, address_bits_required(0x7fffff));
    TEST_ASSERT_EQUAL(25, address_bits_required(0x800000));
    TEST_ASSERT_EQUAL(32, address_bits_required(0x7fffffff));
    TEST_ASSERT_EQUAL(33, address_bits_required(0x80000000));
    TEST_ASSERT_EQUAL(40, address_bits_required(0x7fffffffff));
    TEST_ASSERT_EQUAL(41, address_bits_required(0x8000000000));
    TEST_ASSERT_EQUAL(48, address_bits_required(0x7fffffffffff));
    TEST_ASSERT_EQUAL(49, address_bits_required(0x800000000000));
    TEST_ASSERT_EQUAL(56, address_bits_required(0x7fffffffffffff));
    TEST_ASSERT_EQUAL(57, address_bits_required(0x80000000000000));
    TEST_ASSERT_EQUAL(64, address_bits_required(0x8000000000000000));
    TEST_ASSERT_EQUAL(64, address_bits_required(0x7fffffffffffffff));
    TEST_ASSERT_EQUAL(9, address_bits_required(0xffffffffffffff2f));
    TEST_ASSERT_EQUAL(1, address_bits_required(0x0));
    TEST_ASSERT_EQUAL(1, address_bits_required(0xffffffffffffffff));
}

static void test_message_bytes_required(void) {
    uint8_t msg[14] = {0x1, 0x2, 0xff, 0x0, 0x7f, 0x0, 0x0, 0xff, 0xff, 0xff, 0x80, 0xff, 0xff, 0x0};
    TEST_ASSERT_EQUAL(1, message_bytes_required(msg, 1 << 3));
    TEST_ASSERT_EQUAL(2, message_bytes_required(msg, 2 << 3));
    TEST_ASSERT_EQUAL(3, message_bytes_required(msg, 3 << 3));
    TEST_ASSERT_EQUAL(4, message_bytes_required(msg, 4 << 3));
    TEST_ASSERT_EQUAL(5, message_bytes_required(msg, 5 << 3));
    TEST_ASSERT_EQUAL(5, message_bytes_required(msg, 6 << 3));
    TEST_ASSERT_EQUAL(5, message_bytes_required(msg, 7 << 3));
    TEST_ASSERT_EQUAL(8, message_bytes_required(msg, 8 << 3));
    TEST_ASSERT_EQUAL(8, message_bytes_required(msg, 9 << 3));
    TEST_ASSERT_EQUAL(8, message_bytes_required(msg, 10 << 3));
    TEST_ASSERT_EQUAL(11, message_bytes_required(msg, 11 << 3));
    TEST_ASSERT_EQUAL(11, message_bytes_required(msg, 12 << 3));
    TEST_ASSERT_EQUAL(11, message_bytes_required(msg, 13 << 3));
    TEST_ASSERT_EQUAL(14, message_bytes_required(msg, 14 << 3));

    uint8_t msg1[5] = {0xbd, 0xff, 0xff, 0xff, 0xff};
    TEST_ASSERT_EQUAL(1, message_bytes_required(msg1, 5 << 3));

    /* no valid bits! */
    TEST_ASSERT_EQUAL(0, message_bytes_required(msg1, 0));

    /* 1 to 8 valid bits */
    for (size_t i=1; i<=8; i++)
    {
        TEST_ASSERT_EQUAL(1, message_bytes_required(msg1, i));
    }

    /* 9 to 16 identical bits */
    for (size_t i=9; i<=16; i++)
    {
        TEST_ASSERT_EQUAL(1, message_bytes_required((uint8_t*)"\x00\x00", i));
    }
    TEST_ASSERT_EQUAL(1, message_bytes_required((uint8_t*)"\xff\x01", 9));
    TEST_ASSERT_EQUAL(1, message_bytes_required((uint8_t*)"\xff\x03", 10));
    TEST_ASSERT_EQUAL(1, message_bytes_required((uint8_t*)"\xff\x07", 11));
    TEST_ASSERT_EQUAL(1, message_bytes_required((uint8_t*)"\xff\x0f", 12));
    TEST_ASSERT_EQUAL(1, message_bytes_required((uint8_t*)"\xff\x1f", 13));
    TEST_ASSERT_EQUAL(1, message_bytes_required((uint8_t*)"\xff\x3f", 14));
    TEST_ASSERT_EQUAL(1, message_bytes_required((uint8_t*)"\xff\x7f", 15));
    TEST_ASSERT_EQUAL(1, message_bytes_required((uint8_t*)"\xff\xff", 16));

    /* 17 to 24 identical bits */
    for (size_t i=17; i<=24; i++)
    {
        TEST_ASSERT_EQUAL(1, message_bytes_required((uint8_t*)"\x00\x00\x00", i));
    }
    TEST_ASSERT_EQUAL(1, message_bytes_required((uint8_t*)"\xff\xff\x01", 17));
    TEST_ASSERT_EQUAL(1, message_bytes_required((uint8_t*)"\xff\xff\x03", 18));
    TEST_ASSERT_EQUAL(1, message_bytes_required((uint8_t*)"\xff\xff\x07", 19));
    TEST_ASSERT_EQUAL(1, message_bytes_required((uint8_t*)"\xff\xff\x0f", 20));
    TEST_ASSERT_EQUAL(1, message_bytes_required((uint8_t*)"\xff\xff\x1f", 21));
    TEST_ASSERT_EQUAL(1, message_bytes_required((uint8_t*)"\xff\xff\x3f", 22));
    TEST_ASSERT_EQUAL(1, message_bytes_required((uint8_t*)"\xff\xff\x7f", 23));
    TEST_ASSERT_EQUAL(1, message_bytes_required((uint8_t*)"\xff\xff\xff", 24));

    /* one different bit at the very end of the 3rd byte */
    TEST_ASSERT_EQUAL(3, message_bytes_required((uint8_t*)"\x00\x00\x80", 24));
    TEST_ASSERT_EQUAL(3, message_bytes_required((uint8_t*)"\xff\xff\x7f", 24));
}

static void test_differential_address(void) {
    set_last_address(0x8000000);
    TEST_ASSERT_EQUAL(1, differential_address(0x8000001));
    TEST_ASSERT_EQUAL(0xffffffffffffffff, differential_address(0x7ffffff));
}

static void test_can_set_last_address(void) {
    set_last_address(0x0);
    TEST_ASSERT_EQUAL(1, differential_address(0x1));
    TEST_ASSERT_EQUAL(0x7ffffff, differential_address(0x7ffffff));
    set_last_address(256);
    TEST_ASSERT_EQUAL(-255, differential_address(1));
    TEST_ASSERT_EQUAL(744, differential_address(1000));
}

static void test_bool_array_to_uint32(void) {
    bool array[TE_MAX_NUM_BRANCHES];
    for (size_t i = 0; i < TE_MAX_NUM_BRANCHES; ++i)
        array[i] = true;
    TEST_ASSERT_EQUAL(0x7fffffff, bool_array_to_uint32(array, TE_MAX_NUM_BRANCHES));
    // Zero is a special length meaning TE_MAX_NUM_BRANCHES
    TEST_ASSERT_EQUAL(0x7fffffff, bool_array_to_uint32(array, 0));
    TEST_ASSERT_EQUAL(0xf, bool_array_to_uint32(array, 4));
    TEST_ASSERT_EQUAL(0xfff, bool_array_to_uint32(array, 12));
    TEST_ASSERT_EQUAL(0x1fff, bool_array_to_uint32(array, 13));
    TEST_ASSERT_EQUAL(0x7ffffff, bool_array_to_uint32(array, 27));
    array[0] = false;
    TEST_ASSERT_EQUAL(0x7ffffffe, bool_array_to_uint32(array, TE_MAX_NUM_BRANCHES));
    array[1] = false;
    TEST_ASSERT_EQUAL(0x7ffffffc, bool_array_to_uint32(array, TE_MAX_NUM_BRANCHES));
    array[2] = false;
    TEST_ASSERT_EQUAL(0x7ffffff8, bool_array_to_uint32(array, TE_MAX_NUM_BRANCHES));
    array[3] = false;
    TEST_ASSERT_EQUAL(0x7ffffff0, bool_array_to_uint32(array, TE_MAX_NUM_BRANCHES));

    for (size_t i = 0; i < TE_MAX_NUM_BRANCHES; ++i)
        array[i] = false;
    for (size_t i = 0; i <= TE_MAX_NUM_BRANCHES; ++i)
        TEST_ASSERT_EQUAL(0x0, bool_array_to_uint32(array, i));
    array[15] = true;
    TEST_ASSERT_EQUAL(0x8000, bool_array_to_uint32(array, 20));
}

static void test_uint32_to_bool_array(void) {
    bool array[TE_MAX_NUM_BRANCHES];
    for (size_t i = 0; i < TE_MAX_NUM_BRANCHES; ++i)
        array[i] = false;
    uint32_to_bool_array(0x7fffffff, TE_MAX_NUM_BRANCHES, array);
    for (size_t i = 0; i < TE_MAX_NUM_BRANCHES; ++i)
        TEST_ASSERT_EQUAL(true, array[i]);

    for (uint32_t value = 1U; value <= 0x7fffffffU; value = value << 1U) {
        uint32_to_bool_array(value, TE_MAX_NUM_BRANCHES, array);
        TEST_ASSERT_EQUAL(value, bool_array_to_uint32(array, TE_MAX_NUM_BRANCHES));
    }
}

static void test_bit_functions(void) {
    TEST_ASSERT_EQUAL(0x0, get_bits(0x3c, 0, 1));
    TEST_ASSERT_EQUAL(0x0, get_bits(0x3c, 1, 1));
    TEST_ASSERT_EQUAL(0x1, get_bits(0x3c, 2, 1));
    TEST_ASSERT_EQUAL(0x1, get_bits(0x3c, 3, 1));
    TEST_ASSERT_EQUAL(0x1, get_bits(0x3c, 4, 1));
    TEST_ASSERT_EQUAL(0x1, get_bits(0x3c, 5, 1));
    TEST_ASSERT_EQUAL(0x0, get_bits(0x3c, 6, 1));
    TEST_ASSERT_EQUAL(0x0, get_bits(0x3c, 7, 1));

    TEST_ASSERT_EQUAL(0x3, get_bits(0x3c, 2, 2));
    TEST_ASSERT_EQUAL(0x2, get_bits(0x3c, 1, 2));
    TEST_ASSERT_EQUAL(0x4, get_bits(0x3c, 0, 3));
    TEST_ASSERT_EQUAL(0x6, get_bits(0x3c, 1, 3));
    TEST_ASSERT_EQUAL(0x7, get_bits(0x3c, 2, 3));

    uint8_t result = 0;
    uint8_t value = 0x3;

    for (size_t i = 0; i < 7; ++i) {
        result = 0;
        set_bits(&result, i, 2, value);
        TEST_ASSERT_EQUAL(value << i, result);
    }

    value = 0x5;
    for (size_t i = 0; i < 6; ++i) {
        result = 0;
        set_bits(&result, i, 3, value);
        TEST_ASSERT_EQUAL(value << i, result);
    }

    result = 0;
    value = 0;
    set_bits(&result, 1, 2, value);
    TEST_ASSERT_EQUAL(0x0, result);

    result = 0;
    value = 0x55;
    set_bits(&result, 1, 7, value);
    TEST_ASSERT_EQUAL(value << 1, result);

    result = 0;
    value = 1;
    set_bits(&result, 6, 1, value);
    TEST_ASSERT_EQUAL(value << 6, result);

    set_bits(&result, 3, 1, value);
    TEST_ASSERT_EQUAL((1 << 6) | (1 << 3), result);
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_address_bits_required);
    RUN_TEST(test_message_bytes_required);
    RUN_TEST(test_differential_address);
    RUN_TEST(test_can_set_last_address);
    RUN_TEST(test_bool_array_to_uint32);
    RUN_TEST(test_uint32_to_bool_array);
    RUN_TEST(test_bit_functions);

    return UNITY_END();
}
