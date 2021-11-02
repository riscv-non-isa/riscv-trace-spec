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

#ifndef STATIC_CONFIG_PARSER_H
#define STATIC_CONFIG_PARSER_H

#include <stdint.h>
#include <stdbool.h>

#define NULL_CHAR 0
#define HEADING_CHAR 91
#define NEWLINE_CHAR 10
#define COMMENT_CHAR 35
#define LINE_BUF_ARR_SIZE 256

enum required_config
{
  RC_ARCH_P,
  RC_BPRED_SIZE_P,
  RC_CACHE_SIZE_P,
  RC_CALL_COUNTER_SIZE_P,
  RC_CONTEXT_WIDTH_P,
  RC_TIME_WIDTH_P,
  RC_ECAUSE_WIDTH_P,
  RC_F0S_WIDTH_P,
  RC_IADDRESS_LSB_P,
  RC_IADDRESS_WIDTH_P,
  RC_NOCONTEXT_P,
  RC_NOTIME_P,
  RC_PRIVILEGE_WIDTH_P,
  RC_RETURN_STACK_SIZE_P,
  RC_SIJUMP_P,
  RC__END,
};

enum optional_filtering_config
{
  OFC_COMPARATORS_P,
  OFC_FILTERS_P,
  OFC_ECAUSE_CHOICE_P,
  OFC_FILTER_CONTEXT_P,
  OFC_FILTER_TIME_P,
  OFC_FILTER_EXCINT_P,
  OFC_FILTER_PRIVILEGE_P,
  OFC_FILTER_TVAL_P,
  OFC__END,
};

enum other_recommended_config
{
  ORC_CTYPE_WIDTH_P,
  ORC_ILASTSIZE_WIDTH_P,
  ORC_ITYPE_WIDTH_P,
  ORC_IRETIRE_WIDTH_P,
  ORC_RETIRES_P,
  ORC_TAKEN_BRANCHES_P,
  ORC_IMPDEF_WIDTH_P,
  ORC__END,
};

typedef struct
{
  // Required Attributes
  uint8_t arch_p;
  uint8_t bpred_size_p;
  uint8_t cache_size_p;
  uint8_t call_counter_size_p;
  uint8_t context_width_p;
  uint8_t time_width_p;
  uint8_t ecause_width_p;
  uint8_t f0s_width_p;
  uint8_t iaddress_lsb_p;
  uint8_t iaddress_width_p;
  bool nocontext_p;
  bool notime_p;
  uint8_t privilege_width_p;
  uint8_t return_stack_size_p;
  bool sijump_p;

  // Optional Filtering Attributes
  uint8_t comparators_p;
  uint8_t filters_p;
  uint8_t ecause_choice_p;
  bool filter_context_p;
  bool filter_time_p;
  bool filter_excint_p;
  bool filter_privilege_p;
  bool filter_tval_p;

  // Other Recommended Attributes
  uint8_t ctype_width_p;
  uint8_t ilastsize_width_p;
  uint8_t itype_width_p;
  uint8_t iretire_width_p;
  uint8_t retires_p;
  uint8_t taken_branches_p;
  uint8_t impdef_width_p;
} static_config_t;

void init_static_config_struct(static_config_t *const static_config_p);

bool parse_static_config_file(char *config_filepath, static_config_t *const static_config_p);

#ifdef CMAKE_TESTING_ENABLED
extern void testwrap_clean_str(char *cleaned_line, const char *original_line);
extern void testwrap_remove_whitespace(char *stripped_str, const char *original_str);
extern void testwrap_remove_comments(char *stripped_str, const char *original_str);
extern bool testwrap_is_data_line(const char *line_buf);
extern bool testwrap_check_line_is_required_attrib(const char *param_name, const uint8_t param_value, static_config_t *const static_config_p, uint16_t *required_config_check);
extern bool testwrap_check_line_is_optional_filtering_attrib(const char *param_name, const uint8_t param_value, static_config_t *const static_config_p);
extern bool testwrap_check_line_is_recommended_attrib(const char *param_name, const uint8_t param_value, static_config_t *const static_config_p);
extern bool testwrap_map_line_to_struct(const char *line_buf, static_config_t *const static_config_p, uint16_t *required_config_check_p);
#endif

#endif /* STATIC_CONFIG_PARSER_H */
