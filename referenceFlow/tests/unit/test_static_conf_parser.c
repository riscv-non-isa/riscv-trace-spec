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

#include <stdlib.h>
#include "unity.h"
#include "static_config_parser.h"

void setUp(void)
{
}

void tearDown(void)
{
}

static void test_init_static_config_struct(void)
{
  static_config_t *static_config_p = (static_config_t*)malloc(sizeof(static_config_t));

  init_static_config_struct(static_config_p);

  // Required Attributes
  TEST_ASSERT_EQUAL(0u, static_config_p->arch_p);
  TEST_ASSERT_EQUAL(0u, static_config_p->bpred_size_p);
  TEST_ASSERT_EQUAL(0u, static_config_p->cache_size_p);
  TEST_ASSERT_EQUAL(0u, static_config_p->call_counter_size_p);
  TEST_ASSERT_EQUAL(1u, static_config_p->context_width_p);
  TEST_ASSERT_EQUAL(1u, static_config_p->time_width_p);
  TEST_ASSERT_EQUAL(4u, static_config_p->ecause_width_p);
  TEST_ASSERT_EQUAL(0u, static_config_p->f0s_width_p);
  TEST_ASSERT_EQUAL(1u, static_config_p->iaddress_lsb_p);
  TEST_ASSERT_EQUAL(32u, static_config_p->iaddress_width_p);
  TEST_ASSERT_TRUE(static_config_p->nocontext_p);
  TEST_ASSERT_TRUE(static_config_p->notime_p);
  TEST_ASSERT_EQUAL(3u, static_config_p->privilege_width_p);
  TEST_ASSERT_EQUAL(0u, static_config_p->return_stack_size_p);
  TEST_ASSERT_FALSE(static_config_p->sijump_p);

  // Optional Filtering Attributes
  TEST_ASSERT_EQUAL(1u, static_config_p->comparators_p);
  TEST_ASSERT_EQUAL(1u, static_config_p->filters_p);
  TEST_ASSERT_EQUAL(5u, static_config_p->ecause_choice_p);
  TEST_ASSERT_EQUAL(1u, static_config_p->filter_context_p);
  TEST_ASSERT_EQUAL(1u, static_config_p->filter_time_p);
  TEST_ASSERT_EQUAL(1u, static_config_p->filter_excint_p);
  TEST_ASSERT_EQUAL(1u, static_config_p->filter_privilege_p);
  TEST_ASSERT_EQUAL(1u, static_config_p->filter_tval_p);

  // Other Recommended Attributes
  TEST_ASSERT_EQUAL(2u, static_config_p->ctype_width_p);
  TEST_ASSERT_EQUAL(1u, static_config_p->ilastsize_width_p);
  TEST_ASSERT_EQUAL(4u, static_config_p->itype_width_p);
  TEST_ASSERT_EQUAL(3u, static_config_p->iretire_width_p);
  TEST_ASSERT_EQUAL(1u, static_config_p->retires_p);
  TEST_ASSERT_EQUAL(1u, static_config_p->taken_branches_p);
  TEST_ASSERT_EQUAL(1u, static_config_p->impdef_width_p);

  free(static_config_p);
}

static void test_remove_whitespace(void)
{
  char test_buffer[LINE_BUF_ARR_SIZE];

  const char test_in_1[LINE_BUF_ARR_SIZE] = "Thereissnowhitespacehereatall.";
  const char test_out_1[LINE_BUF_ARR_SIZE] = "Thereissnowhitespacehereatall.";

  const char test_in_2[LINE_BUF_ARR_SIZE] = "This sentence had loads of whitespace. ";
  const char test_out_2[LINE_BUF_ARR_SIZE] = "Thissentencehadloadsofwhitespace.";

  const char test_in_3[LINE_BUF_ARR_SIZE] = "This sentence had whitespace and a\nnewline.";
  const char test_out_3[LINE_BUF_ARR_SIZE] = "Thissentencehadwhitespaceandanewline.";

  const char test_in_4[LINE_BUF_ARR_SIZE] = "This sentence had whitespace and a\ttabs\t.";
  const char test_out_4[LINE_BUF_ARR_SIZE] = "Thissentencehadwhitespaceandatabs.";

  testwrap_remove_whitespace(test_buffer, test_in_1);
  for (size_t i = 0; i < LINE_BUF_ARR_SIZE; i++)
  {
    TEST_ASSERT_EQUAL(test_out_1[i], test_buffer[i]);

    if (test_out_1[i] == '\0')
    {
      break;
    }
  }

  testwrap_remove_whitespace(test_buffer, test_in_2);
  for (size_t i = 0; i < LINE_BUF_ARR_SIZE; i++)
  {
    TEST_ASSERT_EQUAL(test_out_2[i], test_buffer[i]);

    if (test_out_2[i] == '\0')
    {
      break;
    }
  }

  testwrap_remove_whitespace(test_buffer, test_in_3);
  for (size_t i = 0; i < LINE_BUF_ARR_SIZE; i++)
  {
    TEST_ASSERT_EQUAL(test_out_3[i], test_buffer[i]);

    if (test_out_3[i] == '\0')
    {
      break;
    }
  }

  testwrap_remove_whitespace(test_buffer, test_in_4);
  for (size_t i = 0; i < LINE_BUF_ARR_SIZE; i++)
  {
    TEST_ASSERT_EQUAL(test_out_4[i], test_buffer[i]);

    if (test_out_4[i] == '\0')
    {
      break;
    }
  }
}

static void test_remove_comments(void)
{
  char test_buffer[LINE_BUF_ARR_SIZE];

  const char test_in_1[LINE_BUF_ARR_SIZE] = "There's not a comment in this test";
  const char test_out_1[LINE_BUF_ARR_SIZE] = "There's not a comment in this test";

  const char test_in_2[LINE_BUF_ARR_SIZE] = "This test had a comment at the end: # Here it is";
  const char test_out_2[LINE_BUF_ARR_SIZE] = "This test had a comment at the end: ";

  const char test_in_3[LINE_BUF_ARR_SIZE] = "# This test had a comment at the start";
  const char test_out_3[LINE_BUF_ARR_SIZE] = "";

  testwrap_remove_comments(test_buffer, test_in_1);
  for (size_t i = 0; i < LINE_BUF_ARR_SIZE; i++)
  {
    TEST_ASSERT_EQUAL(test_out_1[i], test_buffer[i]);

    if (test_out_1[i] == '\0')
    {
      break;
    }
  }

  testwrap_remove_comments(test_buffer, test_in_2);
  for (size_t i = 0; i < LINE_BUF_ARR_SIZE; i++)
  {
    TEST_ASSERT_EQUAL(test_out_2[i], test_buffer[i]);

    if (test_out_2[i] == '\0')
    {
      break;
    }
  }

  testwrap_remove_comments(test_buffer, test_in_3);
  for (size_t i = 0; i < LINE_BUF_ARR_SIZE; i++)
  {
    TEST_ASSERT_EQUAL(test_out_3[i], test_buffer[i]);

    if (test_out_3[i] == '\0')
    {
      break;
    }
  }
}

static void test_clean_str(void)
{
  char test_buffer[LINE_BUF_ARR_SIZE];

  const char test_in_1[LINE_BUF_ARR_SIZE] = "There's not a comment in this test";
  const char test_out_1[LINE_BUF_ARR_SIZE] = "There'snotacommentinthistest";

  const char test_in_2[LINE_BUF_ARR_SIZE] = "This test had a comment at the end: # Here it is";
  const char test_out_2[LINE_BUF_ARR_SIZE] = "Thistesthadacommentattheend:";

  const char test_in_3[LINE_BUF_ARR_SIZE] = "# This test had a comment at the start";
  const char test_out_3[LINE_BUF_ARR_SIZE] = "";

  const char test_in_4[LINE_BUF_ARR_SIZE] = "This Test had \nnewlines and\ttabs and then a comment# This test had a comment at the start";
  const char test_out_4[LINE_BUF_ARR_SIZE] = "ThisTesthadnewlinesandtabsandthenacomment";

  testwrap_clean_str(test_buffer, test_in_1);
  for (size_t i = 0; i < LINE_BUF_ARR_SIZE; i++)
  {
    TEST_ASSERT_EQUAL(test_out_1[i], test_buffer[i]);

    if (test_out_1[i] == '\0')
    {
      break;
    }
  }

  testwrap_clean_str(test_buffer, test_in_2);
  for (size_t i = 0; i < LINE_BUF_ARR_SIZE; i++)
  {
    TEST_ASSERT_EQUAL(test_out_2[i], test_buffer[i]);

    if (test_out_2[i] == '\0')
    {
      break;
    }
  }

  testwrap_clean_str(test_buffer, test_in_3);
  for (size_t i = 0; i < LINE_BUF_ARR_SIZE; i++)
  {
    TEST_ASSERT_EQUAL(test_out_3[i], test_buffer[i]);

    if (test_out_3[i] == '\0')
    {
      break;
    }
  }

  testwrap_clean_str(test_buffer, test_in_4);
  for (size_t i = 0; i < LINE_BUF_ARR_SIZE; i++)
  {
    TEST_ASSERT_EQUAL(test_out_4[i], test_buffer[i]);

    if (test_out_4[i] == '\0')
    {
      break;
    }
  }
}

static void test_is_data_line(void)
{
  const char true_1[LINE_BUF_ARR_SIZE] = "key=0";
  const char true_2[LINE_BUF_ARR_SIZE] = "some_key=some_value";
  const char true_3[LINE_BUF_ARR_SIZE] = "some_key = withspaces";
  const char true_4[LINE_BUF_ARR_SIZE] = "key=0 # with a comment";

  const char false_1[LINE_BUF_ARR_SIZE] = "[header]";
  const char false_2[LINE_BUF_ARR_SIZE] = "# Just a comment";

  TEST_ASSERT_TRUE(testwrap_is_data_line(true_1));
  TEST_ASSERT_TRUE(testwrap_is_data_line(true_2));
  TEST_ASSERT_TRUE(testwrap_is_data_line(true_3));
  TEST_ASSERT_TRUE(testwrap_is_data_line(true_4));

  TEST_ASSERT_FALSE(testwrap_is_data_line(false_1));
  TEST_ASSERT_FALSE(testwrap_is_data_line(false_2));
}

static void test_check_line_is_required_attrib(void)
{
  static_config_t *static_config_p = (static_config_t*)malloc(sizeof(static_config_t));
  init_static_config_struct(static_config_p);

  // Param values are selected to be a value which isn't defaulted to by the init_static_config_struct() function
  uint8_t param_value = 2u;
  bool param_bool = false;

  uint16_t required_config_check = 0u;
  uint16_t config_check = 0u;
  uint8_t config_idx = 0u;

  TEST_ASSERT(testwrap_check_line_is_required_attrib("arch_p", param_value, static_config_p, &required_config_check));
  TEST_ASSERT_EQUAL(param_value, static_config_p->arch_p);
  config_check += (1u << config_idx);
  TEST_ASSERT_EQUAL(config_check, required_config_check);
  config_idx++;

  TEST_ASSERT(testwrap_check_line_is_required_attrib("bpred_size_p", param_value, static_config_p, &required_config_check));
  TEST_ASSERT_EQUAL(param_value, static_config_p->bpred_size_p);
  config_check += (1u << config_idx);
  TEST_ASSERT_EQUAL(config_check, required_config_check);
  config_idx++;

  TEST_ASSERT(testwrap_check_line_is_required_attrib("cache_size_p", param_value, static_config_p, &required_config_check));
  TEST_ASSERT_EQUAL(param_value, static_config_p->cache_size_p);
  config_check += (1u << config_idx);
  TEST_ASSERT_EQUAL(config_check, required_config_check);
  config_idx++;

  TEST_ASSERT(testwrap_check_line_is_required_attrib("call_counter_size_p", param_value, static_config_p, &required_config_check));
  TEST_ASSERT_EQUAL(param_value, static_config_p->call_counter_size_p);
  config_check += (1u << config_idx);
  TEST_ASSERT_EQUAL(config_check, required_config_check);
  config_idx++;

  TEST_ASSERT(testwrap_check_line_is_required_attrib("context_width_p", param_value, static_config_p, &required_config_check));
  TEST_ASSERT_EQUAL(param_value, static_config_p->context_width_p);
  config_check += (1u << config_idx);
  TEST_ASSERT_EQUAL(config_check, required_config_check);
  config_idx++;

  TEST_ASSERT(testwrap_check_line_is_required_attrib("time_width_p", param_value, static_config_p, &required_config_check));
  TEST_ASSERT_EQUAL(param_value, static_config_p->time_width_p);
  config_check += (1u << config_idx);
  TEST_ASSERT_EQUAL(config_check, required_config_check);
  config_idx++;

  TEST_ASSERT(testwrap_check_line_is_required_attrib("ecause_width_p", param_value, static_config_p, &required_config_check));
  TEST_ASSERT_EQUAL(param_value, static_config_p->ecause_width_p);
  config_check += (1u << config_idx);
  TEST_ASSERT_EQUAL(config_check, required_config_check);
  config_idx++;

  TEST_ASSERT(testwrap_check_line_is_required_attrib("f0s_width_p", param_value, static_config_p, &required_config_check));
  TEST_ASSERT_EQUAL(param_value, static_config_p->f0s_width_p);
  config_check += (1u << config_idx);
  TEST_ASSERT_EQUAL(config_check, required_config_check);
  config_idx++;

  TEST_ASSERT(testwrap_check_line_is_required_attrib("iaddress_lsb_p", param_value, static_config_p, &required_config_check));
  TEST_ASSERT_EQUAL(param_value, static_config_p->iaddress_lsb_p);
  config_check += (1u << config_idx);
  TEST_ASSERT_EQUAL(config_check, required_config_check);
  config_idx++;

  TEST_ASSERT(testwrap_check_line_is_required_attrib("iaddress_width_p", param_value, static_config_p, &required_config_check));
  TEST_ASSERT_EQUAL(param_value, static_config_p->iaddress_width_p);
  config_check += (1u << config_idx);
  TEST_ASSERT_EQUAL(config_check, required_config_check);
  config_idx++;

  TEST_ASSERT(testwrap_check_line_is_required_attrib("nocontext_p", param_bool, static_config_p, &required_config_check));
  TEST_ASSERT_EQUAL(param_bool, static_config_p->nocontext_p);
  config_check += (1u << config_idx);
  TEST_ASSERT_EQUAL(config_check, required_config_check);
  config_idx++;

  TEST_ASSERT(testwrap_check_line_is_required_attrib("notime_p", param_bool, static_config_p, &required_config_check));
  TEST_ASSERT_EQUAL(param_bool, static_config_p->notime_p);
  config_check += (1u << config_idx);
  TEST_ASSERT_EQUAL(config_check, required_config_check);
  config_idx++;

  TEST_ASSERT(testwrap_check_line_is_required_attrib("privilege_width_p", param_value, static_config_p, &required_config_check));
  TEST_ASSERT_EQUAL(param_value, static_config_p->privilege_width_p);
  config_check += (1u << config_idx);
  TEST_ASSERT_EQUAL(config_check, required_config_check);
  config_idx++;

  TEST_ASSERT(testwrap_check_line_is_required_attrib("return_stack_size_p", param_value, static_config_p, &required_config_check));
  TEST_ASSERT_EQUAL(param_value, static_config_p->return_stack_size_p);
  config_check += (1u << config_idx);
  TEST_ASSERT_EQUAL(config_check, required_config_check);
  config_idx++;

  TEST_ASSERT(testwrap_check_line_is_required_attrib("sijump_p", param_bool, static_config_p, &required_config_check));
  TEST_ASSERT_EQUAL(param_bool, static_config_p->sijump_p);
  config_check += (1u << config_idx);
  TEST_ASSERT_EQUAL(config_check, required_config_check);
  config_idx++;

  free(static_config_p);
}

static void test_check_line_is_optional_filtering_attrib(void)
{
  static_config_t *static_config_p = (static_config_t*)malloc(sizeof(static_config_t));
  init_static_config_struct(static_config_p);

  // Param value are selected to be a value which isn't defaulted to by the init_static_config_struct() function
  uint8_t param_value = 0u;

  TEST_ASSERT(testwrap_check_line_is_optional_filtering_attrib("comparators_p", param_value, static_config_p));
  TEST_ASSERT_EQUAL(param_value, static_config_p->comparators_p);

  TEST_ASSERT(testwrap_check_line_is_optional_filtering_attrib("filters_p", param_value, static_config_p));
  TEST_ASSERT_EQUAL(param_value, static_config_p->filters_p);

  TEST_ASSERT(testwrap_check_line_is_optional_filtering_attrib("ecause_choice_p", param_value, static_config_p));
  TEST_ASSERT_EQUAL(param_value, static_config_p->ecause_choice_p);

  TEST_ASSERT(testwrap_check_line_is_optional_filtering_attrib("filter_context_p", param_value, static_config_p));
  TEST_ASSERT_EQUAL(param_value, static_config_p->filter_context_p);

  TEST_ASSERT(testwrap_check_line_is_optional_filtering_attrib("filter_time_p", param_value, static_config_p));
  TEST_ASSERT_EQUAL(param_value, static_config_p->filter_time_p);

  TEST_ASSERT(testwrap_check_line_is_optional_filtering_attrib("filter_excint_p", param_value, static_config_p));
  TEST_ASSERT_EQUAL(param_value, static_config_p->filter_excint_p);

  TEST_ASSERT(testwrap_check_line_is_optional_filtering_attrib("filter_privilege_p", param_value, static_config_p));
  TEST_ASSERT_EQUAL(param_value, static_config_p->filter_privilege_p);

  TEST_ASSERT(testwrap_check_line_is_optional_filtering_attrib("filter_tval_p", param_value, static_config_p));
  TEST_ASSERT_EQUAL(param_value, static_config_p->filter_tval_p);

  free(static_config_p);
}

static void test_check_line_is_recommended_attrib(void)
{
  static_config_t *static_config_p = (static_config_t*)malloc(sizeof(static_config_t));
  init_static_config_struct(static_config_p);

  // Param value are selected to be a value which isn't defaulted to by the init_static_config_struct() function
  uint8_t param_value = 3u;

  TEST_ASSERT(testwrap_check_line_is_recommended_attrib("ctype_width_p", param_value, static_config_p));
  TEST_ASSERT_EQUAL(param_value, static_config_p->ctype_width_p);

  TEST_ASSERT(testwrap_check_line_is_recommended_attrib("ilastsize_width_p", param_value, static_config_p));
  TEST_ASSERT_EQUAL(param_value, static_config_p->ilastsize_width_p);

  param_value = 4u;
  TEST_ASSERT(testwrap_check_line_is_recommended_attrib("itype_width_p", param_value, static_config_p));
  TEST_ASSERT_EQUAL(param_value, static_config_p->itype_width_p);

  param_value = 3u;
  TEST_ASSERT(testwrap_check_line_is_recommended_attrib("iretire_width_p", param_value, static_config_p));
  TEST_ASSERT_EQUAL(param_value, static_config_p->iretire_width_p);

  TEST_ASSERT(testwrap_check_line_is_recommended_attrib("taken_branches_p", param_value, static_config_p));
  TEST_ASSERT_EQUAL(param_value, static_config_p->taken_branches_p);

  TEST_ASSERT(testwrap_check_line_is_recommended_attrib("impdef_width_p", param_value, static_config_p));
  TEST_ASSERT_EQUAL(param_value, static_config_p->impdef_width_p);

  free(static_config_p);
}

static void test_map_line_to_struct(void)
{
  uint16_t required_config_check = 0u;
  static_config_t *static_config_p = (static_config_t*)malloc(sizeof(static_config_t));
  init_static_config_struct(static_config_p);

  TEST_ASSERT_TRUE(testwrap_map_line_to_struct("arch_p=5", static_config_p, &required_config_check));
  TEST_ASSERT_TRUE(testwrap_map_line_to_struct("sijump_p=1", static_config_p, &required_config_check));
  TEST_ASSERT_TRUE(testwrap_map_line_to_struct("comparators_p=1", static_config_p, &required_config_check));
  TEST_ASSERT_TRUE(testwrap_map_line_to_struct("ctype_width_p=1", static_config_p, &required_config_check));

  TEST_ASSERT_TRUE(testwrap_map_line_to_struct("nocontext_p=0 # with a comment", static_config_p, &required_config_check));
  TEST_ASSERT_TRUE(testwrap_map_line_to_struct("filters_p = 0 # with a comment and spaces", static_config_p, &required_config_check));

  TEST_ASSERT_FALSE(testwrap_map_line_to_struct("invalid_key=0", static_config_p, &required_config_check));
  TEST_ASSERT_FALSE(testwrap_map_line_to_struct("arch_p=-1 # invalid value", static_config_p, &required_config_check));
  TEST_ASSERT_FALSE(testwrap_map_line_to_struct("arch_p # no value", static_config_p, &required_config_check));
  TEST_ASSERT_FALSE(testwrap_map_line_to_struct("arch=0 # slightly wrong name", static_config_p, &required_config_check));

  free(static_config_p);
}


int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_init_static_config_struct);
    RUN_TEST(test_remove_whitespace);
    RUN_TEST(test_remove_comments);
    RUN_TEST(test_clean_str);
    RUN_TEST(test_is_data_line);
    RUN_TEST(test_check_line_is_required_attrib);
    RUN_TEST(test_check_line_is_optional_filtering_attrib);
    RUN_TEST(test_check_line_is_recommended_attrib);
    RUN_TEST(test_map_line_to_struct);
    return UNITY_END();
}
