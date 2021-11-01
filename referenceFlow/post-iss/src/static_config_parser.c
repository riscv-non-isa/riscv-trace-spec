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

#define _GNU_SOURCE

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "static_config_parser.h"

static const char *const required_config_var_names[] = {
    [RC_ARCH_P] = "arch_p",
    [RC_BPRED_SIZE_P] = "bpred_size_p",
    [RC_CACHE_SIZE_P] = "cache_size_p",
    [RC_CALL_COUNTER_SIZE_P] = "call_counter_size_p",
    [RC_CONTEXT_WIDTH_P] = "context_width_p",
    [RC_TIME_WIDTH_P] = "time_width_p",
    [RC_ECAUSE_WIDTH_P] = "ecause_width_p",
    [RC_F0S_WIDTH_P] = "f0s_width_p",
    [RC_IADDRESS_LSB_P] = "iaddress_lsb_p",
    [RC_IADDRESS_WIDTH_P] = "iaddress_width_p",
    [RC_NOCONTEXT_P] = "nocontext_p",
    [RC_NOTIME_P] = "notime_p",
    [RC_PRIVILEGE_WIDTH_P] = "privilege_width_p",
    [RC_RETURN_STACK_SIZE_P] = "return_stack_size_p",
    [RC_SIJUMP_P] = "sijump_p",
};

static const char *const optional_filtering_config_var_names[] = {
    [OFC_COMPARATORS_P] = "comparators_p",
    [OFC_FILTERS_P] = "filters_p",
    [OFC_ECAUSE_CHOICE_P] = "ecause_choice_p",
    [OFC_FILTER_CONTEXT_P] = "filter_context_p",
    [OFC_FILTER_TIME_P] = "filter_time_p",
    [OFC_FILTER_EXCINT_P] = "filter_excint_p",
    [OFC_FILTER_PRIVILEGE_P] = "filter_privilege_p",
    [OFC_FILTER_TVAL_P] = "filter_tval_p",
};

static const char *const other_recommended_config_var_names[] = {
    [ORC_CTYPE_WIDTH_P] = "ctype_width_p",
    [ORC_ILASTSIZE_WIDTH_P] = "ilastsize_width_p",
    [ORC_ITYPE_WIDTH_P] = "itype_width_p",
    [ORC_IRETIRE_WIDTH_P] = "iretire_width_p",
    [ORC_RETIRES_P] = "retires_p",
    [ORC_TAKEN_BRANCHES_P] = "taken_branches_p",
    [ORC_IMPDEF_WIDTH_P] = "impdef_width_p",
};

static void remove_whitespace(char *stripped_str, const char *original_str)
{
  while (*original_str != '\0')
  {
    if (!isspace(*original_str))
    {
      *stripped_str = *original_str;
      stripped_str++;
    }

    original_str++;
  }

  *stripped_str = '\0';
}

static void remove_comments(char *stripped_str, const char *original_str)
{
  bool comment_found = false;

  while ((*original_str != '\0') && (!comment_found))
  {
    if (COMMENT_CHAR != *original_str)
    {
      *stripped_str = *original_str;
      stripped_str++;
    }
    else
    {
      comment_found = true;
    }

    original_str++;
  }

  *stripped_str = '\0';
}

static void clean_str(char *cleaned_line, const char *original_line)
{
  char temp_line_buf[LINE_BUF_ARR_SIZE];
  remove_comments(temp_line_buf, original_line);
  remove_whitespace(cleaned_line, temp_line_buf);
}

static bool is_data_line(const char *line_buf)
{
  char clean_line_buf[LINE_BUF_ARR_SIZE];
  clean_str(clean_line_buf, line_buf);

  if ((clean_line_buf[0] == NULL_CHAR) ||
      (clean_line_buf[0] == HEADING_CHAR) ||
      (clean_line_buf[0] == NEWLINE_CHAR) ||
      (clean_line_buf[0] == COMMENT_CHAR))
  {
    return false;
  }
  return true;
}

static bool check_required_config_found(const uint16_t required_config_check)
{
  bool required_values_found = true;
  uint16_t check_val = 0u;
  uint16_t arg_position = 0u;

  for (size_t i = 0; i < RC__END; i++)
  {
    arg_position = (1u << i);
    check_val = required_config_check & arg_position;
    if (check_val != arg_position)
    {
      required_values_found = false;
      printf("Warning  -- Missing Required Attribute: %s. Defaulting to initialization values\n", required_config_var_names[i]);
      return required_values_found;
    }

    check_val = 0u;
    arg_position = 0u;
  }

  return required_values_found;
}

static bool check_line_is_required_attrib(const char *param_name, const uint8_t param_value, static_config_t *const static_config_p, uint16_t *required_config_check)
{
  bool attribute_found = false;

  for (size_t param_idx = 0; param_idx < RC__END; param_idx++)
  {
    if (strcmp(param_name, required_config_var_names[param_idx]) == 0)
    {
      attribute_found = true;

      // Keep track of which required attributes have been assigned.
      *required_config_check += (1u << param_idx);

      // We matched a string variable. Now assign to which one it was
      switch (param_idx)
      {
      case RC_ARCH_P:
        static_config_p->arch_p = param_value;
        break;

      case RC_BPRED_SIZE_P:
        static_config_p->bpred_size_p = param_value;
        break;

      case RC_CACHE_SIZE_P:
        static_config_p->cache_size_p = param_value;
        break;

      case RC_CALL_COUNTER_SIZE_P:
        static_config_p->call_counter_size_p = param_value;
        break;

      case RC_CONTEXT_WIDTH_P:
        static_config_p->context_width_p = param_value;
        break;

      case RC_TIME_WIDTH_P:
        static_config_p->time_width_p = param_value;
        break;

      case RC_ECAUSE_WIDTH_P:
        static_config_p->ecause_width_p = param_value;
        break;

      case RC_F0S_WIDTH_P:
        static_config_p->f0s_width_p = param_value;
        break;

      case RC_IADDRESS_LSB_P:
        static_config_p->iaddress_lsb_p = param_value;
        break;

      case RC_IADDRESS_WIDTH_P:
        static_config_p->iaddress_width_p = param_value;
        break;

      case RC_NOCONTEXT_P:
        assert((0u == param_value) || (1u == param_value));
        static_config_p->nocontext_p = (bool)param_value;
        break;

      case RC_NOTIME_P:
        assert((0u == param_value) || (1u == param_value));
        static_config_p->notime_p = (bool)param_value;
        break;

      case RC_PRIVILEGE_WIDTH_P:
        static_config_p->privilege_width_p = param_value;
        break;

      case RC_RETURN_STACK_SIZE_P:
        static_config_p->return_stack_size_p = param_value;
        break;

      case RC_SIJUMP_P:
        assert((0u == param_value) || (1u == param_value));
        static_config_p->sijump_p = (bool)param_value;
        break;

      case RC__END:
        // We shouldn't ever hit this one
        attribute_found = false;
        break;

      default:
        // shouldn't ever hit this either
        attribute_found = false;
        assert(attribute_found);
        break;
      }

      return attribute_found;
    }
  }

  return attribute_found;
}

static bool check_line_is_optional_filtering_attrib(const char *param_name, const uint8_t param_value, static_config_t *const static_config_p)
{
  bool attribute_found = false;

  for (size_t param_idx = 0; param_idx < OFC__END; param_idx++)
  {
    if (strcmp(param_name, optional_filtering_config_var_names[param_idx]) == 0)
    {
      attribute_found = true;

      switch (param_idx)
      {
      case OFC_COMPARATORS_P:
        static_config_p->comparators_p = param_value;
        break;

      case OFC_FILTERS_P:
        static_config_p->filters_p = param_value;
        break;

      case OFC_ECAUSE_CHOICE_P:
        static_config_p->ecause_choice_p = param_value;
        break;

      case OFC_FILTER_CONTEXT_P:
        assert((0u == param_value) || (1u == param_value));
        static_config_p->filter_context_p = (bool)param_value;
        break;

      case OFC_FILTER_TIME_P:
        assert((0u == param_value) || (1u == param_value));
        static_config_p->filter_time_p = (bool)param_value;
        break;

      case OFC_FILTER_EXCINT_P:
        assert((0u == param_value) || (1u == param_value));
        static_config_p->filter_excint_p = (bool)param_value;
        break;

      case OFC_FILTER_PRIVILEGE_P:
        assert((0u == param_value) || (1u == param_value));
        static_config_p->filter_privilege_p = (bool)param_value;
        break;

      case OFC_FILTER_TVAL_P:
        assert((0u == param_value) || (1u == param_value));
        static_config_p->filter_tval_p = (bool)param_value;
        break;

      case OFC__END:
        attribute_found = false;
        break;

      default:
        attribute_found = false;
        break;
      }

      assert(attribute_found);
      return attribute_found;
    }
  }

  return attribute_found;
}

static bool check_line_is_recommended_attrib(const char *param_name, const uint8_t param_value, static_config_t *const static_config_p)
{
  bool attribute_found = false;

  for (size_t param_idx = 0; param_idx < ORC__END; param_idx++)
  {
    if (strcmp(param_name, other_recommended_config_var_names[param_idx]) == 0)
    {
      attribute_found = true;

      switch (param_idx)
      {
      case ORC_CTYPE_WIDTH_P:
        static_config_p->ctype_width_p = param_value;
        break;

      case ORC_ILASTSIZE_WIDTH_P:
        static_config_p->ilastsize_width_p = param_value;
        break;

      case ORC_ITYPE_WIDTH_P:
        if ( (3 != param_value) && (4 != param_value) )
        {
          printf("itype_width_p must equal 3 or 4. Parsed value: %d\n", param_value);
          attribute_found = false;
        }
        else
        {
          static_config_p->itype_width_p = param_value;
        }
        break;

      case ORC_IRETIRE_WIDTH_P:
        static_config_p->iretire_width_p = param_value;
        break;

      case ORC_RETIRES_P:
        assert(param_value > 0);
        static_config_p->retires_p = param_value;
        break;

      case ORC_TAKEN_BRANCHES_P:
        static_config_p->taken_branches_p = param_value;
        break;

      case ORC_IMPDEF_WIDTH_P:
        static_config_p->impdef_width_p = param_value;
        break;

      case ORC__END:
        attribute_found = false;
        break;

      default:
        attribute_found = false;
        break;
      }

      return attribute_found;
    }
  }

  return attribute_found;
}

static bool map_line_to_struct(const char *line_buf, static_config_t *const static_config_p, uint16_t *required_config_check_p)
{
  bool mapping_found = true;

  char clean_line_buf[LINE_BUF_ARR_SIZE];
  clean_str(clean_line_buf, line_buf);

  char *param_value_str;
  strtok_r(clean_line_buf, "=", &param_value_str);

  int16_t param_value;
  if ((sscanf(param_value_str, "%hd", &param_value) != 1) || (param_value < 0))
  {
    // param value should be uint8_t
    return false;
  }

  if (!check_line_is_required_attrib(clean_line_buf, param_value, static_config_p, required_config_check_p))
  {
    if (!check_line_is_optional_filtering_attrib(clean_line_buf, param_value, static_config_p))
    {
      if (!check_line_is_recommended_attrib(clean_line_buf, param_value, static_config_p))
      {
        mapping_found = false;
      }
    }
  }

  return mapping_found;
}

void init_static_config_struct(static_config_t *const static_config_p)
{
  assert(static_config_p);

  // Required Attributes
  static_config_p->arch_p = 0u;
  static_config_p->bpred_size_p = 0u;
  static_config_p->cache_size_p = 0u;
  static_config_p->call_counter_size_p = 0u;
  static_config_p->context_width_p = 1u;
  static_config_p->time_width_p = 1u;
  static_config_p->ecause_width_p = 4u;
  static_config_p->f0s_width_p = 0u;
  static_config_p->iaddress_lsb_p = 1u;
  static_config_p->iaddress_width_p = 32u;
  static_config_p->nocontext_p = true;
  static_config_p->notime_p = true;
  static_config_p->privilege_width_p = 3u;
  static_config_p->return_stack_size_p = 0u;
  static_config_p->sijump_p = false;

  // Optional Filtering Attributes
  static_config_p->comparators_p = 1u;
  static_config_p->filters_p = 1u;
  static_config_p->ecause_choice_p = 5u;
  static_config_p->filter_context_p = 1u;
  static_config_p->filter_time_p = 1u;
  static_config_p->filter_excint_p = 1u;
  static_config_p->filter_privilege_p = 1u;
  static_config_p->filter_tval_p = 1u;

  // Other Recommended Attributes
  static_config_p->ctype_width_p = 2u;
  static_config_p->ilastsize_width_p = 1u;
  static_config_p->itype_width_p = 4u;
  static_config_p->iretire_width_p = 3u;
  static_config_p->retires_p = 1u;
  static_config_p->taken_branches_p = 1u;
  static_config_p->impdef_width_p = 1u;
}

bool parse_static_config_file(char *config_filepath, static_config_t *const static_config_p)
{
  bool parse_success = false;

  FILE *config_file = fopen(config_filepath, "r");

  char line_buf[LINE_BUF_ARR_SIZE];

  static uint16_t required_config_check = 0u;

  if (0 == config_file)
  {
    printf("Cannot open config file: %s\n", config_filepath);
    exit(-1);
  }
  else
  {
    parse_success = true;
  }

  while (fgets(line_buf, sizeof(line_buf), config_file))
  {
    if (true == is_data_line(line_buf))
    {
      parse_success = map_line_to_struct(line_buf, static_config_p, &required_config_check);
    }
    if (!parse_success)
    {
      break;
    }
  }

  fclose(config_file);

  check_required_config_found(required_config_check);

  return parse_success;
}

#ifdef CMAKE_TESTING_ENABLED
void testwrap_clean_str(char *cleaned_line, const char *original_line)
{
  clean_str(cleaned_line, original_line);
}

void testwrap_remove_whitespace(char *stripped_str, const char *original_str)
{
  remove_whitespace(stripped_str, original_str);
}

void testwrap_remove_comments(char *stripped_str, const char *original_str)
{
  remove_comments(stripped_str, original_str);
}

bool testwrap_is_data_line(const char *line_buf)
{
  return is_data_line(line_buf);
}

bool testwrap_check_line_is_required_attrib(const char *param_name, const uint8_t param_value, static_config_t *const static_config_p, uint16_t *required_config_check)
{
  return check_line_is_required_attrib(param_name, param_value, static_config_p, required_config_check);
}

bool testwrap_check_line_is_optional_filtering_attrib(const char *param_name, const uint8_t param_value, static_config_t *const static_config_p)
{
  return check_line_is_optional_filtering_attrib(param_name, param_value, static_config_p);
}

bool testwrap_check_line_is_recommended_attrib(const char *param_name, const uint8_t param_value, static_config_t *const static_config_p)
{
  return check_line_is_recommended_attrib(param_name, param_value, static_config_p);
}

bool testwrap_map_line_to_struct(const char *line_buf, static_config_t *const static_config_p, uint16_t *required_config_check_p)
{
  return map_line_to_struct(line_buf, static_config_p, required_config_check_p);
}
#endif
