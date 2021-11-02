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

#ifndef POST_ISS_H
#define POST_ISS_H

#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "static_config_parser.h"
#include "riscv-disas.h"

#define MAX_RETIRES 16
#define POST_ISS_MAX_OUTPUT_LINE_LEN 512
#define POST_ISS_MAX_FILENAME_LEN 128
#define POST_ISS_HEADER_COLS_TYPES 11 // Number of header column names
#define POST_ISS_SPIKE_ISS_HEADER_COUNT 7

typedef enum
{
  iss_parse_header,
  iss_parse_line_success,
  iss_parse_fail = -1,
} iss_parse_result_t;

typedef struct
{
  const char *col_name;
  size_t n_repeats;
  bool is_last;
} post_iss_header_t;

typedef struct
{
  uint64_t address;
  uint64_t instruction;
  uint8_t privilege;
  bool is_exception;
  uint8_t exception_value;
  uint8_t trap_value;
  bool is_interrupt;

  // Housekeeping
  uint8_t inst_length;
  bool is_branch;
  bool is_return;
  bool is_jump;
  bool is_inferable_jump;
  bool is_uninferable_jump;
  bool is_sequentially_inferable_jump;
  bool is_call;
  bool is_tail_call;
  bool is_co_routine_swap;
  bool is_other_jump;
} iss_content_t;

typedef enum
{
  ITYPE_NONE = 0,
  ITYPE_EXCEPTION = 1,
  ITYPE_INTERRUPT = 2,
  ITYPE_EXCEPTION_OR_INTERRUPT_RETURN = 3,
  ITYPE_NONTAKEN_BRANCH = 4,
  ITYPE_TAKEN_BRANCH = 5,
  ITYPE_UNINFERABLE_JUMP = 6,
  ITYPE_RESERVED = 7,
  ITYPE_UNINFERABLE_CALL = 8,
  ITYPE_INFERABLE_CALL = 9,
  ITYPE_UNINFERABLE_TAIL_CALL = 10,
  ITYPE_INFERABLE_TAIL_CALL = 11,
  ITYPE_CO_ROUTINE_SWAP = 12,
  ITYPE_RETURN = 13,
  ITYPE_OTHER_UNINFERABLE_JUMP = 14,
  ITYPE_OTHER_INFERABLE_JUMP = 15,
  ITYPE_INVALID,
} itype_t;

typedef struct
{
  itype_t itype[MAX_RETIRES];
  uint16_t cause;
  uint64_t tval;
  uint8_t priv;
  uint64_t iaddr[MAX_RETIRES];
  uint32_t context;
  uint64_t time;
  uint8_t ctype;
  bool sijump[MAX_RETIRES];
  uint8_t iretire[MAX_RETIRES];
  uint8_t ilastsize[MAX_RETIRES];
} post_iss_t;

/*
 * The following structure is used to hold the disassembled information
 * for a single RISC-V instruction.
 *
 * Empirically, 84 bytes is the length of the longest
 * disassembled line observed thus far, but other (unseen)
 * instructions could be longer (e.g. custom instructions)!
 */
typedef struct
{
    rv_decode   decode;     /* from the riscv-disassembler repo */
    unsigned    length;     /* instruction size (in bytes) */
    bool        custom;     /* true if a custom instruction */
    char        line[88];   /* disassembly line for printing */
} disasm_instruction_t;

void init_iss_content_t(iss_content_t *const iss_content);
void init_post_iss_t(post_iss_t *const post_iss_s, const bool use_itype_none);
void set_rv_isa_32bit(const bool set_isa_32);
bool post_iss_parse_config(char *conf_file);
void process_iss_file(const char *const in_file);

#ifdef CMAKE_TESTING_ENABLED
extern void post_iss_reset_test_config(void);
extern void post_iss_set_test_config(static_config_t *config_data_p);
extern void testwrap_set_post_iss_header_struct(post_iss_header_t *header_p, const char *col_name, const uint64_t n_repeats, const bool is_last);
extern uint64_t testwrap_define_post_iss_header(post_iss_header_t header_p[]);
extern void testwrap_generate_output_header(char *line);
extern char *testwrap_generate_encoder_output_filename(const char *const input_filename);
extern void testwrap_swap_current_and_previous(uint8_t *current_val_p, uint8_t *previous_val_p);
extern void testwrap_init_iss_content_t(iss_content_t *const iss_content);
extern void testwrap_init_disasm_instruction_t(disasm_instruction_t *const dec_inst_s);
extern iss_parse_result_t testwrap_parse_iss_line(const char *const line, iss_content_t *const iss_content);
extern int testwrap_was_prev_branch_taken(bool previous_was_branch, uint64_t prev_address, uint8_t prev_inst_length, uint64_t current_address);
extern bool testwrap_assign_current_itype_value(const itype_t type, const itype_t current_itype);
extern itype_t testwrap_infer_itype(iss_content_t *current_iss_content, iss_content_t *previous_iss_content);
extern itype_t testwrap_infer_previous_itype(iss_content_t *current_iss_content, iss_content_t *previous_iss_content);

extern rv_isa testwrap_set_rv_isa_32bit(const bool set_isa_32);
#endif

#endif /* POST_ISS_H */
