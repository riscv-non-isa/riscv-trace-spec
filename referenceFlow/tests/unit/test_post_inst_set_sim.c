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
#include "post_inst_set_sim.h"
#include "static_config_parser.h"

void setUp(void)
{
}

void tearDown(void)
{
}

static void test_set_post_iss_header_struct(void)
{
  post_iss_header_t *header_p = (post_iss_header_t *)malloc(sizeof(post_iss_header_t));

  testwrap_set_post_iss_header_struct(header_p, "column_name", 10, true);

  TEST_ASSERT_EQUAL("column_name", header_p->col_name);
  TEST_ASSERT_EQUAL(10, header_p->n_repeats);
  TEST_ASSERT_EQUAL(true, header_p->is_last);

  testwrap_set_post_iss_header_struct(header_p, "another_name", 5, false);

  TEST_ASSERT_EQUAL("another_name", header_p->col_name);
  TEST_ASSERT_EQUAL(5, header_p->n_repeats);
  TEST_ASSERT_EQUAL(false, header_p->is_last);

  free(header_p);
}

static void test_define_post_iss_header(void)
{
  static_config_t *config_data_p = (static_config_t *)malloc(sizeof(static_config_t));
  init_static_config_struct(config_data_p);
  post_iss_set_test_config(config_data_p);

  post_iss_header_t header_s[POST_ISS_HEADER_COLS_TYPES];
  memset(&header_s, 0, (POST_ISS_HEADER_COLS_TYPES * sizeof(post_iss_header_t)));

  TEST_ASSERT_EQUAL(7u, testwrap_define_post_iss_header(header_s));

  // context enables both the "context" and "ctype" headers to be enabled
  config_data_p->nocontext_p = 0;
  post_iss_set_test_config(config_data_p);
  TEST_ASSERT_EQUAL(9u, testwrap_define_post_iss_header(header_s));

  config_data_p->notime_p = 0;
  post_iss_set_test_config(config_data_p);
  TEST_ASSERT_EQUAL(10u, testwrap_define_post_iss_header(header_s));

  config_data_p->sijump_p = 1;
  post_iss_set_test_config(config_data_p);
  TEST_ASSERT_EQUAL(11u, testwrap_define_post_iss_header(header_s));

  free(config_data_p);
  post_iss_reset_test_config();
}

static void test_generate_output_header(void)
{
  char test_buffer[POST_ISS_MAX_OUTPUT_LINE_LEN];

  const char base_header[POST_ISS_MAX_OUTPUT_LINE_LEN] = "itype_0,cause,tval,priv,iaddr_0,iretire_0,ilastsize_0\n";
  const char context_enabled[POST_ISS_MAX_OUTPUT_LINE_LEN] = "itype_0,cause,tval,priv,iaddr_0,context,ctype,iretire_0,ilastsize_0\n";
  const char time_enabled[POST_ISS_MAX_OUTPUT_LINE_LEN] = "itype_0,cause,tval,priv,iaddr_0,time,iretire_0,ilastsize_0\n";
  const char sijump_enabled[POST_ISS_MAX_OUTPUT_LINE_LEN] = "itype_0,cause,tval,priv,iaddr_0,sijump_0,iretire_0,ilastsize_0\n";
  const char base_multiple_retirements[POST_ISS_MAX_OUTPUT_LINE_LEN] = "itype_0,itype_1,cause,tval,priv,iaddr_0,iaddr_1,iretire_0,iretire_1,ilastsize_0,ilastsize_1\n";
  const char all_multiple_retirements[POST_ISS_MAX_OUTPUT_LINE_LEN] = "itype_0,itype_1,cause,tval,priv,iaddr_0,iaddr_1,context,time,ctype,sijump_0,sijump_1,iretire_0,iretire_1,ilastsize_0,ilastsize_1\n";

  static_config_t *config_data_p = (static_config_t *)malloc(sizeof(static_config_t));
  init_static_config_struct(config_data_p);

  // Default config settings
  post_iss_set_test_config(config_data_p);
  testwrap_generate_output_header(test_buffer);
  for (size_t i = 0; i < LINE_BUF_ARR_SIZE; i++)
  {
    TEST_ASSERT_EQUAL(base_header[i], test_buffer[i]);

    if (base_header[i] == '\0')
    {
      break;
    }
  }
  init_static_config_struct(config_data_p);
  post_iss_reset_test_config();

  // with context
  config_data_p->nocontext_p = false;
  post_iss_set_test_config(config_data_p);
  testwrap_generate_output_header(test_buffer);
  for (size_t i = 0; i < LINE_BUF_ARR_SIZE; i++)
  {
    TEST_ASSERT_EQUAL(context_enabled[i], test_buffer[i]);

    if (context_enabled[i] == '\0')
    {
      break;
    }
  }
  init_static_config_struct(config_data_p);
  post_iss_reset_test_config();

  // with time
  config_data_p->notime_p = false;
  post_iss_set_test_config(config_data_p);
  testwrap_generate_output_header(test_buffer);
  for (size_t i = 0; i < LINE_BUF_ARR_SIZE; i++)
  {
    TEST_ASSERT_EQUAL(time_enabled[i], test_buffer[i]);

    if (time_enabled[i] == '\0')
    {
      break;
    }
  }
  init_static_config_struct(config_data_p);
  post_iss_reset_test_config();

  // with sequential jumps
  config_data_p->sijump_p = true;
  post_iss_set_test_config(config_data_p);
  testwrap_generate_output_header(test_buffer);
  for (size_t i = 0; i < LINE_BUF_ARR_SIZE; i++)
  {
    TEST_ASSERT_EQUAL(sijump_enabled[i], test_buffer[i]);

    if (sijump_enabled[i] == '\0')
    {
      break;
    }
  }
  init_static_config_struct(config_data_p);
  post_iss_reset_test_config();

  // base multiple retirements
  config_data_p->retires_p = 2u;
  post_iss_set_test_config(config_data_p);
  testwrap_generate_output_header(test_buffer);
  for (size_t i = 0; i < LINE_BUF_ARR_SIZE; i++)
  {
    TEST_ASSERT_EQUAL(base_multiple_retirements[i], test_buffer[i]);

    if (base_multiple_retirements[i] == '\0')
    {
      break;
    }
  }
  init_static_config_struct(config_data_p);
  post_iss_reset_test_config();

  // all multiple retirements
  config_data_p->sijump_p = true;
  config_data_p->nocontext_p = false;
  config_data_p->notime_p = false;
  config_data_p->retires_p = 2u;
  post_iss_set_test_config(config_data_p);
  testwrap_generate_output_header(test_buffer);
  for (size_t i = 0; i < LINE_BUF_ARR_SIZE; i++)
  {
    TEST_ASSERT_EQUAL(all_multiple_retirements[i], test_buffer[i]);

    if (all_multiple_retirements[i] == '\0')
    {
      break;
    }
  }
  init_static_config_struct(config_data_p);
  post_iss_reset_test_config();

  free(config_data_p);
  post_iss_reset_test_config();
}

static void test_generate_encoder_output_filename(void)
{
  char *test_buffer = NULL;

  const char test_in_1[POST_ISS_MAX_FILENAME_LEN] = "test_filename";
  const char test_out_1[POST_ISS_MAX_FILENAME_LEN] = "test_filename.encoder_input";

  const char test_in_2[POST_ISS_MAX_FILENAME_LEN] = "filename.previous_ext";
  const char test_out_2[POST_ISS_MAX_FILENAME_LEN] = "filename.encoder_input";

  const char test_in_3[POST_ISS_MAX_FILENAME_LEN] = "filename with spaces";
  const char test_out_3[POST_ISS_MAX_FILENAME_LEN] = "filename with spaces.encoder_input";

  test_buffer = testwrap_generate_encoder_output_filename(test_in_1);
  for (size_t i = 0; i < POST_ISS_MAX_FILENAME_LEN; i++)
  {
    TEST_ASSERT_EQUAL(test_out_1[i], test_buffer[i]);

    if (test_out_1[i] == '\0')
    {
      break;
    }
  }

  test_buffer = testwrap_generate_encoder_output_filename(test_in_2);
  for (size_t i = 0; i < POST_ISS_MAX_FILENAME_LEN; i++)
  {
    TEST_ASSERT_EQUAL(test_out_2[i], test_buffer[i]);

    if (test_out_2[i] == '\0')
    {
      break;
    }
  }

  test_buffer = testwrap_generate_encoder_output_filename(test_in_3);
  for (size_t i = 0; i < POST_ISS_MAX_FILENAME_LEN; i++)
  {
    TEST_ASSERT_EQUAL(test_out_3[i], test_buffer[i]);

    if (test_out_3[i] == '\0')
    {
      break;
    }
  }
}

static void test_swap_current_and_previous(void)
{
  const uint8_t impossible_value = 10u;
  uint8_t current_val = impossible_value;
  uint8_t previous_val = impossible_value;

  uint8_t last_internal_c;
  uint8_t last_internal_p;

  // Test that two values are different and either 1 or 0
  testwrap_swap_current_and_previous(&current_val, &previous_val);
  TEST_ASSERT_NOT_EQUAL(impossible_value, current_val);
  TEST_ASSERT_NOT_EQUAL(impossible_value, previous_val);
  TEST_ASSERT_NOT_EQUAL(current_val, previous_val);

  if (current_val == 1u)
  {
    TEST_ASSERT_EQUAL(0u, previous_val);
    last_internal_c = 1u;
    last_internal_p = 0u;
  }
  else
  {
    TEST_ASSERT_EQUAL(0u, current_val);
    TEST_ASSERT_EQUAL(1u, previous_val);
    last_internal_c = 0u;
    last_internal_p = 1u;
  }

  testwrap_swap_current_and_previous(&current_val, &previous_val);
  TEST_ASSERT_NOT_EQUAL(current_val, previous_val);
  TEST_ASSERT_EQUAL(current_val, last_internal_p);
  TEST_ASSERT_EQUAL(previous_val, last_internal_c);
}

static void test_init_iss_content_t(void)
{
  iss_content_t *iss_data = (iss_content_t *)malloc(sizeof(iss_content_t));

  testwrap_init_iss_content_t(iss_data);

  TEST_ASSERT_EQUAL(0u, iss_data->address);
  TEST_ASSERT_EQUAL(0u, iss_data->instruction);
  TEST_ASSERT_EQUAL(0u, iss_data->privilege);
  TEST_ASSERT_FALSE(iss_data->is_exception);
  TEST_ASSERT_EQUAL(0u, iss_data->exception_value);
  TEST_ASSERT_EQUAL(0u, iss_data->trap_value);
  TEST_ASSERT_FALSE(iss_data->is_interrupt);
  TEST_ASSERT_EQUAL(0u, iss_data->inst_length);
  TEST_ASSERT_FALSE(iss_data->is_branch);
  TEST_ASSERT_FALSE(iss_data->is_return);
  TEST_ASSERT_FALSE(iss_data->is_jump);
  TEST_ASSERT_FALSE(iss_data->is_inferable_jump);
  TEST_ASSERT_FALSE(iss_data->is_uninferable_jump);
  TEST_ASSERT_FALSE(iss_data->is_sequentially_inferable_jump);
  TEST_ASSERT_FALSE(iss_data->is_call);
  TEST_ASSERT_FALSE(iss_data->is_tail_call);
  TEST_ASSERT_FALSE(iss_data->is_co_routine_swap);
  TEST_ASSERT_FALSE(iss_data->is_other_jump);

  free(iss_data);
}

static void test_init_disasm_instruction_t(void)
{
  disasm_instruction_t *dec_inst_p = (disasm_instruction_t *)malloc(sizeof(disasm_instruction_t));

  testwrap_init_disasm_instruction_t(dec_inst_p);

  TEST_ASSERT_EQUAL(0u, dec_inst_p->length);
  TEST_ASSERT_FALSE(dec_inst_p->custom);

  for (size_t i = 0; i < sizeof(dec_inst_p->line); i++)
  {
    TEST_ASSERT_EQUAL(0u, dec_inst_p->line[i]);
  }

  free(dec_inst_p);
}

static void test_init_post_iss_t_with_invalid_itype(void)
{
  post_iss_t *post_iss_p = (post_iss_t *)malloc(sizeof(post_iss_t));

  const bool use_none_itype = false;
  init_post_iss_t(post_iss_p, use_none_itype);

  TEST_ASSERT_EQUAL(0u, post_iss_p->cause);
  TEST_ASSERT_EQUAL(0u, post_iss_p->tval);
  TEST_ASSERT_EQUAL(0u, post_iss_p->priv);
  TEST_ASSERT_EQUAL(0u, post_iss_p->context);
  TEST_ASSERT_EQUAL(0u, post_iss_p->time);
  TEST_ASSERT_EQUAL(0u, post_iss_p->ctype);

  for (size_t i = 0; i < MAX_RETIRES; i++)
  {
    TEST_ASSERT_EQUAL(ITYPE_INVALID, post_iss_p->itype[i]);
  }

  for (size_t i = 0; i < MAX_RETIRES; i++)
  {
    TEST_ASSERT_EQUAL(0u, post_iss_p->iaddr[i]);
  }

  for (size_t i = 0; i < MAX_RETIRES; i++)
  {
    TEST_ASSERT_FALSE(post_iss_p->sijump[i]);
  }

  for (size_t i = 0; i < MAX_RETIRES; i++)
  {
    TEST_ASSERT_EQUAL(0u, post_iss_p->iretire[i]);
  }

  for (size_t i = 0; i < MAX_RETIRES; i++)
  {
    TEST_ASSERT_EQUAL(0u, post_iss_p->ilastsize[i]);
  }

  free(post_iss_p);
}

static void test_init_post_iss_t_with_none_itype(void)
{
  post_iss_t *post_iss_p = (post_iss_t *)malloc(sizeof(post_iss_t));

  const bool use_none_itype = true;
  init_post_iss_t(post_iss_p, use_none_itype);

  TEST_ASSERT_EQUAL(0u, post_iss_p->cause);
  TEST_ASSERT_EQUAL(0u, post_iss_p->tval);
  TEST_ASSERT_EQUAL(0u, post_iss_p->priv);
  TEST_ASSERT_EQUAL(0u, post_iss_p->context);
  TEST_ASSERT_EQUAL(0u, post_iss_p->time);
  TEST_ASSERT_EQUAL(0u, post_iss_p->ctype);

  for (size_t i = 0; i < MAX_RETIRES; i++)
  {
    TEST_ASSERT_EQUAL(ITYPE_NONE, post_iss_p->itype[i]);
  }

  for (size_t i = 0; i < MAX_RETIRES; i++)
  {
    TEST_ASSERT_EQUAL(0u, post_iss_p->iaddr[i]);
  }

  for (size_t i = 0; i < MAX_RETIRES; i++)
  {
    TEST_ASSERT_FALSE(post_iss_p->sijump[i]);
  }

  for (size_t i = 0; i < MAX_RETIRES; i++)
  {
    TEST_ASSERT_EQUAL(0u, post_iss_p->iretire[i]);
  }

  for (size_t i = 0; i < MAX_RETIRES; i++)
  {
    TEST_ASSERT_EQUAL(0u, post_iss_p->ilastsize[i]);
  }

  free(post_iss_p);
}

static void test_parse_iss_line(void)
{
  // These values are all in hex
  const char test_line_1[POST_ISS_MAX_OUTPUT_LINE_LEN] = "1,1000,100,3,0,0,0,0\n";
  const char test_line_2[POST_ISS_MAX_OUTPUT_LINE_LEN] = "1,5000,500,2,1,1,0,0\n";
  const char test_line_3[POST_ISS_MAX_OUTPUT_LINE_LEN] = "1,2000,800,4,0,0,1,1\n";
  const char test_header_line[POST_ISS_MAX_OUTPUT_LINE_LEN] = "VALID,ADDRESS,INSN,PRIVILEGE,EXCEPTION,ECAUSE,TVAL,INTERRUPT\n";
  const char test_line_short[POST_ISS_MAX_OUTPUT_LINE_LEN] = "1,0,0\n";
  const char test_line_long[POST_ISS_MAX_OUTPUT_LINE_LEN] = "1,0,0,0,0,0,0,0,0,0\n";

  iss_content_t *iss_data_p = (iss_content_t*)malloc(sizeof(iss_content_t));

  TEST_ASSERT_EQUAL(iss_parse_line_success, testwrap_parse_iss_line(test_line_1, iss_data_p));
  TEST_ASSERT_EQUAL(0x1000, iss_data_p->address);
  TEST_ASSERT_EQUAL(0x100, iss_data_p->instruction);
  TEST_ASSERT_EQUAL(0x3, iss_data_p->privilege);
  TEST_ASSERT_FALSE(iss_data_p->is_exception);
  TEST_ASSERT_EQUAL(0x0, iss_data_p->exception_value);
  TEST_ASSERT_EQUAL(0x0u, iss_data_p->trap_value);
  TEST_ASSERT_FALSE(iss_data_p->is_interrupt);

  TEST_ASSERT_EQUAL(iss_parse_line_success, testwrap_parse_iss_line(test_line_2, iss_data_p));
  TEST_ASSERT_EQUAL(0x5000, iss_data_p->address);
  TEST_ASSERT_EQUAL(0x500, iss_data_p->instruction);
  TEST_ASSERT_EQUAL(0x2, iss_data_p->privilege);
  TEST_ASSERT_TRUE(iss_data_p->is_exception);
  TEST_ASSERT_EQUAL(0x1, iss_data_p->exception_value);
  TEST_ASSERT_EQUAL(0x0, iss_data_p->trap_value);
  TEST_ASSERT_FALSE(iss_data_p->is_interrupt);

  TEST_ASSERT_EQUAL(iss_parse_line_success, testwrap_parse_iss_line(test_line_3, iss_data_p));
  TEST_ASSERT_EQUAL(0x2000, iss_data_p->address);
  TEST_ASSERT_EQUAL(0x800, iss_data_p->instruction);
  TEST_ASSERT_EQUAL(0x4, iss_data_p->privilege);
  TEST_ASSERT_FALSE(iss_data_p->is_exception);
  TEST_ASSERT_EQUAL(0x0, iss_data_p->exception_value);
  TEST_ASSERT_EQUAL(0x1, iss_data_p->trap_value);
  TEST_ASSERT_TRUE(iss_data_p->is_interrupt);

  TEST_ASSERT_EQUAL(iss_parse_header, testwrap_parse_iss_line(test_header_line, iss_data_p));
  // Parsing the header more than once causes failure
  TEST_ASSERT_EQUAL(iss_parse_fail, testwrap_parse_iss_line(test_header_line, iss_data_p));

  TEST_ASSERT_EQUAL(iss_parse_fail, testwrap_parse_iss_line(test_line_long, iss_data_p));
  TEST_ASSERT_EQUAL(iss_parse_fail, testwrap_parse_iss_line(test_line_short, iss_data_p));

  free(iss_data_p);
}

static void test_was_prev_branch_taken(void)
{
  bool previous_was_branch = false;
  const uint64_t prev_address = 0x1000;
  uint8_t prev_inst_length = 0x2;
  uint64_t current_address = 0x1002;

  // Wasn't a branch instruction.
  TEST_ASSERT_EQUAL(-1, testwrap_was_prev_branch_taken(previous_was_branch, prev_address, prev_inst_length, current_address));

  // Was a branch, but wasn't taken.
  previous_was_branch = true;
  TEST_ASSERT_EQUAL(0u, testwrap_was_prev_branch_taken(previous_was_branch, prev_address, prev_inst_length, current_address));

  // Was a branch and it was taken. Jumping forwards
  current_address = 0x2000;
  TEST_ASSERT_EQUAL(1u, testwrap_was_prev_branch_taken(previous_was_branch, prev_address, prev_inst_length, current_address));

  // Was a branch and it was taken. Jumping backwards
  current_address = 0x500;
  TEST_ASSERT_EQUAL(1u, testwrap_was_prev_branch_taken(previous_was_branch, prev_address, prev_inst_length, current_address));

  // Was a branch and it was taken. Jumping forwards (different inst length)
  current_address = 0x1002;
  prev_inst_length = 0x4;
  TEST_ASSERT_EQUAL(1u, testwrap_was_prev_branch_taken(previous_was_branch, prev_address, prev_inst_length, current_address));
}

static void test_assign_current_itype_value(void)
{
  itype_t new_itype = ITYPE_RETURN;
  itype_t current_itype = ITYPE_NONTAKEN_BRANCH;

  TEST_ASSERT_TRUE(testwrap_assign_current_itype_value(new_itype, current_itype));

  new_itype = ITYPE_INVALID;
  TEST_ASSERT_FALSE(testwrap_assign_current_itype_value(new_itype, current_itype));
}

static void test_infer_expection_itype(void)
{
  itype_t expected_itype = ITYPE_EXCEPTION;

  iss_content_t *current_iss_data_p = (iss_content_t*)malloc(sizeof(iss_content_t));
  iss_content_t *previous_iss_data_p = NULL;

  static_config_t *config_data_p = (static_config_t *)malloc(sizeof(static_config_t));
  init_static_config_struct(config_data_p);
  post_iss_set_test_config(config_data_p);

  init_iss_content_t(current_iss_data_p);

  current_iss_data_p->is_exception = true;

  itype_t inferred_itype = testwrap_infer_itype(current_iss_data_p, previous_iss_data_p);

  TEST_ASSERT_EQUAL(expected_itype, inferred_itype);

  free(current_iss_data_p);
  free(config_data_p);
}

static void test_infer_interrupt_itype(void)
{
  itype_t expected_itype = ITYPE_INTERRUPT;

  iss_content_t *current_iss_data_p = (iss_content_t*)malloc(sizeof(iss_content_t));
  iss_content_t *previous_iss_data_p = NULL;

  static_config_t *config_data_p = (static_config_t *)malloc(sizeof(static_config_t));
  init_static_config_struct(config_data_p);
  post_iss_set_test_config(config_data_p);

  init_iss_content_t(current_iss_data_p);

  current_iss_data_p->is_interrupt = true;

  itype_t inferred_itype = testwrap_infer_itype(current_iss_data_p, previous_iss_data_p);

  TEST_ASSERT_EQUAL(expected_itype, inferred_itype);

  free(current_iss_data_p);
  free(config_data_p);
}

static void test_infer_return_from_expection_itype(void)
{
  itype_t expected_itype = ITYPE_EXCEPTION_OR_INTERRUPT_RETURN;

  iss_content_t *current_iss_data_p = (iss_content_t*)malloc(sizeof(iss_content_t));
  iss_content_t *previous_iss_data_p =(iss_content_t*)malloc(sizeof(iss_content_t));

  static_config_t *config_data_p = (static_config_t *)malloc(sizeof(static_config_t));
  init_static_config_struct(config_data_p);
  post_iss_set_test_config(config_data_p);

  init_iss_content_t(current_iss_data_p);
  init_iss_content_t(previous_iss_data_p);

  previous_iss_data_p->is_exception = true;
  current_iss_data_p->is_return = true;

  itype_t inferred_itype = testwrap_infer_itype(current_iss_data_p, previous_iss_data_p);

  TEST_ASSERT_EQUAL(expected_itype, inferred_itype);

  free(current_iss_data_p);
  free(previous_iss_data_p);
  free(config_data_p);
}

static void test_infer_return_from_interrupt_itype(void)
{
  itype_t expected_itype = ITYPE_EXCEPTION_OR_INTERRUPT_RETURN;

  iss_content_t *current_iss_data_p = (iss_content_t*)malloc(sizeof(iss_content_t));
  iss_content_t *previous_iss_data_p =(iss_content_t*)malloc(sizeof(iss_content_t));

  static_config_t *config_data_p = (static_config_t *)malloc(sizeof(static_config_t));
  init_static_config_struct(config_data_p);
  post_iss_set_test_config(config_data_p);

  init_iss_content_t(current_iss_data_p);
  init_iss_content_t(previous_iss_data_p);

  previous_iss_data_p->is_interrupt = true;
  current_iss_data_p->is_return = true;

  itype_t inferred_itype = testwrap_infer_itype(current_iss_data_p, previous_iss_data_p);

  TEST_ASSERT_EQUAL(expected_itype, inferred_itype);

  free(current_iss_data_p);
  free(previous_iss_data_p);
  free(config_data_p);
}

static void test_infer_previous_itype_not_a_branch(void)
{
  itype_t expected_itype = ITYPE_NONE;

  iss_content_t *current_iss_data_p = (iss_content_t*)malloc(sizeof(iss_content_t));
  iss_content_t *previous_iss_data_p =(iss_content_t*)malloc(sizeof(iss_content_t));

  static_config_t *config_data_p = (static_config_t *)malloc(sizeof(static_config_t));
  init_static_config_struct(config_data_p);
  post_iss_set_test_config(config_data_p);

  init_iss_content_t(current_iss_data_p);
  init_iss_content_t(previous_iss_data_p);

  itype_t inferred_itype = testwrap_infer_previous_itype(current_iss_data_p, previous_iss_data_p);

  TEST_ASSERT_EQUAL(expected_itype, inferred_itype);

  free(current_iss_data_p);
  free(previous_iss_data_p);
  free(config_data_p);
}

static void test_infer_previous_itype_non_taken_branch(void)
{
  itype_t expected_itype = ITYPE_NONTAKEN_BRANCH;

  iss_content_t *current_iss_data_p = (iss_content_t*)malloc(sizeof(iss_content_t));
  iss_content_t *previous_iss_data_p =(iss_content_t*)malloc(sizeof(iss_content_t));

  static_config_t *config_data_p = (static_config_t *)malloc(sizeof(static_config_t));
  init_static_config_struct(config_data_p);
  post_iss_set_test_config(config_data_p);

  init_iss_content_t(current_iss_data_p);
  init_iss_content_t(previous_iss_data_p);

  previous_iss_data_p->is_branch = true;
  previous_iss_data_p->address = 0x10000;
  previous_iss_data_p->inst_length = 0x4;

  current_iss_data_p->address = 0x10004;

  itype_t inferred_itype = testwrap_infer_previous_itype(current_iss_data_p, previous_iss_data_p);

  TEST_ASSERT_EQUAL(expected_itype, inferred_itype);

  free(current_iss_data_p);
  free(previous_iss_data_p);
  free(config_data_p);
}

static void test_infer_previous_itype_taken_branch(void)
{
  itype_t expected_itype = ITYPE_TAKEN_BRANCH;

  iss_content_t *current_iss_data_p = (iss_content_t*)malloc(sizeof(iss_content_t));
  iss_content_t *previous_iss_data_p =(iss_content_t*)malloc(sizeof(iss_content_t));

  static_config_t *config_data_p = (static_config_t *)malloc(sizeof(static_config_t));
  init_static_config_struct(config_data_p);
  post_iss_set_test_config(config_data_p);

  init_iss_content_t(current_iss_data_p);
  init_iss_content_t(previous_iss_data_p);

  previous_iss_data_p->is_branch = true;
  previous_iss_data_p->address = 0x10000;
  previous_iss_data_p->inst_length = 0x4;

  current_iss_data_p->address = 0x20000;

  itype_t inferred_itype = testwrap_infer_previous_itype(current_iss_data_p, previous_iss_data_p);

  TEST_ASSERT_EQUAL(expected_itype, inferred_itype);

  // Check if the jump was backwards too.
  current_iss_data_p->address = 0x5000;

  inferred_itype = testwrap_infer_previous_itype(current_iss_data_p, previous_iss_data_p);

  TEST_ASSERT_EQUAL(expected_itype, inferred_itype);

  free(current_iss_data_p);
  free(previous_iss_data_p);
  free(config_data_p);
}

static void test_infer_uninferable_jump_itype_width_3(void)
{
  itype_t expected_itype = ITYPE_UNINFERABLE_JUMP;

  iss_content_t *current_iss_data_p = (iss_content_t*)malloc(sizeof(iss_content_t));
  iss_content_t *previous_iss_data_p = NULL;

  static_config_t *config_data_p = (static_config_t *)malloc(sizeof(static_config_t));
  init_static_config_struct(config_data_p);

  // Set itype width to 3
  config_data_p->itype_width_p = 3;
  post_iss_set_test_config(config_data_p);

  init_iss_content_t(current_iss_data_p);

  current_iss_data_p->is_jump = true;
  current_iss_data_p->is_uninferable_jump = true;

  itype_t inferred_itype = testwrap_infer_itype(current_iss_data_p, previous_iss_data_p);

  TEST_ASSERT_EQUAL(expected_itype, inferred_itype);

  free(current_iss_data_p);
  free(config_data_p);
}

static void test_infer_uninferable_call_itype(void)
{
  itype_t expected_itype = ITYPE_UNINFERABLE_CALL;

  iss_content_t *current_iss_data_p = (iss_content_t*)malloc(sizeof(iss_content_t));
  iss_content_t *previous_iss_data_p = NULL;

  static_config_t *config_data_p = (static_config_t *)malloc(sizeof(static_config_t));
  init_static_config_struct(config_data_p);

  // Set itype width to 4
  config_data_p->itype_width_p = 4;
  post_iss_set_test_config(config_data_p);

  init_iss_content_t(current_iss_data_p);

  current_iss_data_p->is_jump = true;
  current_iss_data_p->is_uninferable_jump = true;
  current_iss_data_p->is_call = true;

  itype_t inferred_itype = testwrap_infer_itype(current_iss_data_p, previous_iss_data_p);

  TEST_ASSERT_EQUAL(expected_itype, inferred_itype);

  free(current_iss_data_p);
  free(config_data_p);
}

static void test_infer_inferable_call_itype(void)
{
  itype_t expected_itype = ITYPE_INFERABLE_CALL;

  iss_content_t *current_iss_data_p = (iss_content_t*)malloc(sizeof(iss_content_t));
  iss_content_t *previous_iss_data_p = NULL;

  static_config_t *config_data_p = (static_config_t *)malloc(sizeof(static_config_t));
  init_static_config_struct(config_data_p);

  // Set itype width to 4
  config_data_p->itype_width_p = 4;
  post_iss_set_test_config(config_data_p);

  init_iss_content_t(current_iss_data_p);

  current_iss_data_p->is_jump = true;
  current_iss_data_p->is_inferable_jump = true;
  current_iss_data_p->is_call = true;

  itype_t inferred_itype = testwrap_infer_itype(current_iss_data_p, previous_iss_data_p);

  TEST_ASSERT_EQUAL(expected_itype, inferred_itype);

  free(current_iss_data_p);
  free(config_data_p);
}

static void test_infer_uninferable_tail_call_itype(void)
{
  itype_t expected_itype = ITYPE_UNINFERABLE_TAIL_CALL;

  iss_content_t *current_iss_data_p = (iss_content_t*)malloc(sizeof(iss_content_t));
  iss_content_t *previous_iss_data_p = NULL;

  static_config_t *config_data_p = (static_config_t *)malloc(sizeof(static_config_t));
  init_static_config_struct(config_data_p);

  // Set itype width to 4
  config_data_p->itype_width_p = 4;
  post_iss_set_test_config(config_data_p);

  init_iss_content_t(current_iss_data_p);

  current_iss_data_p->is_jump = true;
  current_iss_data_p->is_uninferable_jump = true;
  current_iss_data_p->is_tail_call = true;

  itype_t inferred_itype = testwrap_infer_itype(current_iss_data_p, previous_iss_data_p);

  TEST_ASSERT_EQUAL(expected_itype, inferred_itype);

  free(current_iss_data_p);
  free(config_data_p);
}

static void test_infer_inferable_tail_call_itype(void)
{
  itype_t expected_itype = ITYPE_INFERABLE_TAIL_CALL;

  iss_content_t *current_iss_data_p = (iss_content_t*)malloc(sizeof(iss_content_t));
  iss_content_t *previous_iss_data_p = NULL;

  static_config_t *config_data_p = (static_config_t *)malloc(sizeof(static_config_t));
  init_static_config_struct(config_data_p);

  // Set itype width to 4
  config_data_p->itype_width_p = 4;
  post_iss_set_test_config(config_data_p);

  init_iss_content_t(current_iss_data_p);

  current_iss_data_p->is_jump = true;
  current_iss_data_p->is_inferable_jump = true;
  current_iss_data_p->is_tail_call = true;

  itype_t inferred_itype = testwrap_infer_itype(current_iss_data_p, previous_iss_data_p);

  TEST_ASSERT_EQUAL(expected_itype, inferred_itype);

  free(current_iss_data_p);
  free(config_data_p);
}

static void test_infer_coroutine_swap_itype(void)
{
  itype_t expected_itype = ITYPE_CO_ROUTINE_SWAP;

  iss_content_t *current_iss_data_p = (iss_content_t*)malloc(sizeof(iss_content_t));
  iss_content_t *previous_iss_data_p = NULL;

  static_config_t *config_data_p = (static_config_t *)malloc(sizeof(static_config_t));
  init_static_config_struct(config_data_p);

  // Set itype width to 4
  config_data_p->itype_width_p = 4;
  post_iss_set_test_config(config_data_p);

  init_iss_content_t(current_iss_data_p);

  current_iss_data_p->is_jump = true;
  current_iss_data_p->is_uninferable_jump = true;
  current_iss_data_p->is_co_routine_swap = true;

  itype_t inferred_itype = testwrap_infer_itype(current_iss_data_p, previous_iss_data_p);

  TEST_ASSERT_EQUAL(expected_itype, inferred_itype);

  free(current_iss_data_p);
  free(config_data_p);
}

static void test_infer_return_itype(void)
{
  itype_t expected_itype = ITYPE_RETURN;

  iss_content_t *current_iss_data_p = (iss_content_t*)malloc(sizeof(iss_content_t));
  iss_content_t *previous_iss_data_p = NULL;

  static_config_t *config_data_p = (static_config_t *)malloc(sizeof(static_config_t));
  init_static_config_struct(config_data_p);

  // Set itype width to 4
  config_data_p->itype_width_p = 4;
  post_iss_set_test_config(config_data_p);

  init_iss_content_t(current_iss_data_p);

  current_iss_data_p->is_jump = true;
  current_iss_data_p->is_uninferable_jump = true;
  current_iss_data_p->is_return = true;

  itype_t inferred_itype = testwrap_infer_itype(current_iss_data_p, previous_iss_data_p);

  TEST_ASSERT_EQUAL(expected_itype, inferred_itype);

  free(current_iss_data_p);
  free(config_data_p);
}

static void test_infer_other_uninferable_itype(void)
{
  itype_t expected_itype = ITYPE_OTHER_UNINFERABLE_JUMP;

  iss_content_t *current_iss_data_p = (iss_content_t*)malloc(sizeof(iss_content_t));
  iss_content_t *previous_iss_data_p = NULL;

  static_config_t *config_data_p = (static_config_t *)malloc(sizeof(static_config_t));
  init_static_config_struct(config_data_p);

  // Set itype width to 4
  config_data_p->itype_width_p = 4;
  post_iss_set_test_config(config_data_p);

  init_iss_content_t(current_iss_data_p);

  current_iss_data_p->is_jump = true;
  current_iss_data_p->is_uninferable_jump = true;
  current_iss_data_p->is_other_jump = true;

  itype_t inferred_itype = testwrap_infer_itype(current_iss_data_p, previous_iss_data_p);

  TEST_ASSERT_EQUAL(expected_itype, inferred_itype);

  free(current_iss_data_p);
  free(config_data_p);
}

static void test_infer_other_inferable_itype(void)
{
  itype_t expected_itype = ITYPE_OTHER_INFERABLE_JUMP;

  iss_content_t *current_iss_data_p = (iss_content_t*)malloc(sizeof(iss_content_t));
  iss_content_t *previous_iss_data_p = NULL;

  static_config_t *config_data_p = (static_config_t *)malloc(sizeof(static_config_t));
  init_static_config_struct(config_data_p);

  // Set itype width to 4
  config_data_p->itype_width_p = 4;
  post_iss_set_test_config(config_data_p);

  init_iss_content_t(current_iss_data_p);

  current_iss_data_p->is_jump = true;
  current_iss_data_p->is_inferable_jump = true;
  current_iss_data_p->is_other_jump = true;

  itype_t inferred_itype = testwrap_infer_itype(current_iss_data_p, previous_iss_data_p);

  TEST_ASSERT_EQUAL(expected_itype, inferred_itype);

  free(current_iss_data_p);
  free(config_data_p);
}

static void test_set_rv_isa_32bit(void)
{
  bool enable_32bit = true;
  rv_isa isa_mode = testwrap_set_rv_isa_32bit(enable_32bit);
  TEST_ASSERT_EQUAL(rv32, isa_mode);

  enable_32bit = false;
  isa_mode = testwrap_set_rv_isa_32bit(enable_32bit);
  TEST_ASSERT_EQUAL(rv64, isa_mode);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_set_post_iss_header_struct);
  RUN_TEST(test_define_post_iss_header);
  RUN_TEST(test_generate_output_header);
  RUN_TEST(test_generate_encoder_output_filename);
  RUN_TEST(test_swap_current_and_previous);
  RUN_TEST(test_init_iss_content_t);
  RUN_TEST(test_init_disasm_instruction_t);
  RUN_TEST(test_init_post_iss_t_with_invalid_itype);
  RUN_TEST(test_init_post_iss_t_with_none_itype);
  RUN_TEST(test_parse_iss_line);
  RUN_TEST(test_was_prev_branch_taken);
  RUN_TEST(test_assign_current_itype_value);
  RUN_TEST(test_infer_expection_itype);
  RUN_TEST(test_infer_interrupt_itype);
  RUN_TEST(test_infer_return_from_expection_itype);
  RUN_TEST(test_infer_return_from_interrupt_itype);
  RUN_TEST(test_infer_previous_itype_not_a_branch);
  RUN_TEST(test_infer_previous_itype_non_taken_branch);
  RUN_TEST(test_infer_previous_itype_taken_branch);
  RUN_TEST(test_infer_uninferable_jump_itype_width_3);
  RUN_TEST(test_infer_uninferable_call_itype);
  RUN_TEST(test_infer_inferable_call_itype);
  RUN_TEST(test_infer_uninferable_tail_call_itype);
  RUN_TEST(test_infer_inferable_tail_call_itype);
  RUN_TEST(test_infer_coroutine_swap_itype);
  RUN_TEST(test_infer_return_itype);
  RUN_TEST(test_infer_other_uninferable_itype);
  RUN_TEST(test_infer_other_inferable_itype);
  RUN_TEST(test_set_rv_isa_32bit);
  return UNITY_END();
}
