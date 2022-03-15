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

#define _GNU_SOURCE // For basename() from string.h

#include "post_inst_set_sim.h"
#include "riscv-disas.h"

static char output_line_buf[POST_ISS_MAX_OUTPUT_LINE_LEN];
static char filename_buf[POST_ISS_MAX_FILENAME_LEN];

static uint8_t current = 0u;
static uint8_t previous = 1u;
static iss_content_t iss_data[2];
static disasm_instruction_t decoded_inst_s[2];
static post_iss_t post_iss_data[2];

static static_config_t config_data_s;
static bool config_parsed = false;

static rv_isa isa = rv64;

static void set_post_iss_header_struct(post_iss_header_t *header_p, const char *col_name, const uint64_t n_repeats, const bool is_last)
{
  assert(header_p);

  header_p->col_name = col_name;
  header_p->n_repeats = n_repeats;
  header_p->is_last = is_last;
}

static uint64_t define_post_iss_header(post_iss_header_t header_p[])
{
  assert(config_parsed);

  uint64_t n_header_types = 0u;
  uint64_t n_retires = config_data_s.retires_p;
  assert(n_retires > 0);

  bool no_context = config_data_s.nocontext_p;
  bool no_time = config_data_s.notime_p;
  bool sijump = config_data_s.sijump_p;

  set_post_iss_header_struct(header_p, "itype", n_retires, false);
  header_p++;
  n_header_types++;

  set_post_iss_header_struct(header_p, "cause", 0, false);
  header_p++;
  n_header_types++;

  set_post_iss_header_struct(header_p, "tval", 0, false);
  header_p++;
  n_header_types++;

  set_post_iss_header_struct(header_p, "priv", 0, false);
  header_p++;
  n_header_types++;

  set_post_iss_header_struct(header_p, "iaddr", n_retires, false);
  header_p++;
  n_header_types++;

  if (!no_context)
  {
    set_post_iss_header_struct(header_p, "context", 0, false);
    header_p++;
    n_header_types++;
  }
  if (!no_time)
  {
    set_post_iss_header_struct(header_p, "time", 0, false);
    header_p++;
    n_header_types++;
  }
  if (!no_context)
  {
    set_post_iss_header_struct(header_p, "ctype", 0, false);
    header_p++;
    n_header_types++;
  }

  if (sijump)
  {
    set_post_iss_header_struct(header_p, "sijump", n_retires, false);
    header_p++;
    n_header_types++;
  }

  set_post_iss_header_struct(header_p, "iretire", n_retires, false);
  header_p++;
  n_header_types++;

  set_post_iss_header_struct(header_p, "ilastsize", n_retires, true);
  header_p++;
  n_header_types++;

  return n_header_types;
}

static void generate_output_header(char *line)
{
  assert(config_parsed);

  uint64_t chars_written = 0u;
  uint64_t chars_available = POST_ISS_MAX_OUTPUT_LINE_LEN;
  uint64_t n_header_types = 0u;

  post_iss_header_t header_s[POST_ISS_HEADER_COLS_TYPES];
  memset(&header_s, 0, (POST_ISS_HEADER_COLS_TYPES * sizeof(post_iss_header_t)));
  n_header_types = define_post_iss_header(header_s);

  for (size_t i = 0; i < n_header_types; i++)
  {
    if (header_s[i].n_repeats > 0)
    {
      for (size_t n = 0; n < header_s[i].n_repeats; n++)
      {
        chars_written = snprintf(line, chars_available, "%s_%ld,", header_s[i].col_name, n);

        chars_available -= chars_written;
        assert(chars_available < POST_ISS_MAX_OUTPUT_LINE_LEN);

        line += chars_written;
      }
    }
    else
    {
      chars_written = snprintf(line, chars_available, "%s,", header_s[i].col_name);

      chars_available -= chars_written;
      assert(chars_available < POST_ISS_MAX_OUTPUT_LINE_LEN);

      line += chars_written;
    }

    if (header_s[i].is_last)
    {
      line -= 1;
      *line = '\n';
      line += 1;
      *line = '\0';

      chars_written += 1;
      chars_available -= chars_written;
      assert(chars_available < POST_ISS_MAX_OUTPUT_LINE_LEN);
    }
  }
}

static char *generate_encoder_output_filename(const char *const input_filename)
{
  char *extension = rindex(input_filename, '.');
  if (extension != NULL)
  {
    *extension = '\0';
  }

  snprintf(filename_buf, POST_ISS_MAX_FILENAME_LEN, "%s.encoder_input", basename(input_filename));

  return filename_buf;
}

static void swap_current_and_previous(void)
{
  assert((1u == current) || (0u == current));
  assert((1u == previous) || (0u == previous));
  assert(current != previous);

  current = (current + 1) % 2;
  previous = (previous + 1) % 2;

  assert((1u == current) || (0u == current));
  assert((1u == previous) || (0u == previous));
  assert(current != previous);
}

void init_iss_content_t(iss_content_t *const iss_content)
{
  assert(iss_content);

  iss_content->address = 0u;
  iss_content->instruction = 0u;
  iss_content->privilege = 0u;
  iss_content->is_exception = false;
  iss_content->exception_value = 0u;
  iss_content->trap_value = 0u;
  iss_content->is_interrupt = false;

  iss_content->inst_length = 0u;
  iss_content->is_branch = false;
  iss_content->is_return = false;
  iss_content->is_jump = false;
  iss_content->is_inferable_jump = false;
  iss_content->is_uninferable_jump = false;
  iss_content->is_sequentially_inferable_jump = false;
  iss_content->is_call = false;
  iss_content->is_tail_call = false;
  iss_content->is_co_routine_swap = false;
  iss_content->is_other_jump = false;
}

void init_post_iss_t(post_iss_t *const post_iss_s, const bool use_itype_none)
{
  assert(post_iss_s);

  itype_t init_itype;
  if (use_itype_none)
  {
    init_itype = ITYPE_NONE;
  }
  else
  {
    init_itype = ITYPE_INVALID;
  }

  for (size_t i = 0; i < MAX_RETIRES; i++)
  {
    post_iss_s->itype[i] = init_itype;
  }

  post_iss_s->cause = 0u;
  post_iss_s->tval = 0u;
  post_iss_s->priv = 0u;
  memset(post_iss_s->iaddr, 0u, sizeof(post_iss_s->iaddr));
  post_iss_s->context = 0u;
  post_iss_s->time = 0u;
  post_iss_s->ctype = 0u;
  memset(post_iss_s->sijump, false, sizeof(post_iss_s->sijump));
  memset(post_iss_s->iretire, 0u, sizeof(post_iss_s->iretire));
  memset(post_iss_s->ilastsize, 0u, sizeof(post_iss_s->ilastsize));
}


static void init_iss_content_array(void)
{
  assert((1u == current) || (0u == current));
  assert((1u == previous) || (0u == previous));
  assert(current != previous);

  init_iss_content_t(&iss_data[current]);
  init_iss_content_t(&iss_data[previous]);
}

static void init_disasm_instruction_t(disasm_instruction_t *const dec_inst_s)
{
  assert(dec_inst_s);

  dec_inst_s->length = 0u;
  dec_inst_s->custom = false;
  memset(dec_inst_s->line, 0, sizeof(dec_inst_s->line));
}

static void init_te_decodoed_instruct_array(void)
{
  assert((1u == current) || (0u == current));
  assert((1u == previous) || (0u == previous));
  assert(current != previous);

  init_disasm_instruction_t(&decoded_inst_s[current]);
  init_disasm_instruction_t(&decoded_inst_s[previous]);
}

static void init_post_iss_array(void)
{
  assert((1u == current) || (0u == current));
  assert((1u == previous) || (0u == previous));
  assert(current != previous);

  bool use_itype_none = false;
  init_post_iss_t(&post_iss_data[current], use_itype_none);

  use_itype_none = true;
  init_post_iss_t(&post_iss_data[previous], use_itype_none);
}

static void init_current_data_structs(void)
{
  init_disasm_instruction_t(&decoded_inst_s[current]);
  init_iss_content_t(&iss_data[current]);
  init_post_iss_t(&post_iss_data[current], false);
}

static bool disassemble_inst(uint64_t inst, uint64_t address)
{
  bool valid_op_code = true;

  rv_decode *rv_dec = &(decoded_inst_s[current].decode);

  rv_dec->op = disasm_inst_adv(rv_dec, NULL, 0, isa, address, inst, false);

  if (rv_op_illegal == rv_dec->op)
  {
    valid_op_code = false;
  }

  decoded_inst_s[current].length = inst_length(inst);

  return valid_op_code;
}

static iss_parse_result_t parse_iss_line(const char *const line, iss_content_t *const iss_content)
{
  assert(iss_content);

  int is_exception = 0;
  int is_interrupt = 0;
  static bool header_parsed = false;
  errno = 0;

  // Checking correct number of input values
  int n_split_fields = 0u;
  const int comma_delim = 44u; // ASCII for ',' is 44.
  for (size_t i = 0; i < POST_ISS_MAX_OUTPUT_LINE_LEN; i++)
  {
    if (0 == line[i])
    {
      break;
    }

    if (comma_delim == line[i])
    {
      n_split_fields++;
    }
  }
  if (POST_ISS_SPIKE_ISS_HEADER_COUNT != n_split_fields)
  {
    perror("Error reading Instruction Set Simulator File: incorrect number of fields");
    return iss_parse_fail;
  }

  int n_vals = sscanf(line,
                      "1,%lx,%lx,%hhx,%d,%hhx,%hhx,%d",
                      &iss_content->address,
                      &iss_content->instruction,
                      &iss_content->privilege,
                      &is_exception,
                      &iss_content->exception_value,
                      &iss_content->trap_value,
                      &is_interrupt);

  if ((n_vals == 0) && header_parsed == false)
  {
    header_parsed = true;
    return iss_parse_header;
  }

  iss_content->is_exception = (bool)is_exception;
  iss_content->is_interrupt = (bool)is_interrupt;

  if ((errno != 0) || (n_vals != POST_ISS_SPIKE_ISS_HEADER_COUNT))
  {
    perror("Error reading Instruction Set Simulator File");
    return iss_parse_fail;
  }

  return iss_parse_line_success;
}


static bool is_branch(const disasm_instruction_t * const instr)
{
    assert(instr);
    return (instr->decode.op == rv_op_beq)    ||
        (instr->decode.op == rv_op_bne)    ||
        (instr->decode.op == rv_op_blt)    ||
        (instr->decode.op == rv_op_bge)    ||
        (instr->decode.op == rv_op_bltu)   ||
        (instr->decode.op == rv_op_bgeu)   ||
        (instr->decode.op == rv_op_c_beqz) ||
        (instr->decode.op == rv_op_c_bnez);
}

static bool is_inferrable_jump(const disasm_instruction_t * const instr)
{
    assert(instr);

    return (instr->decode.op == rv_op_jal)    ||
        (instr->decode.op == rv_op_c_jal)  ||
        (instr->decode.op == rv_op_c_j)    ||
        ( (instr->decode.op == rv_op_jalr) &&
          (0 == instr->decode.rs1));
}

static bool is_uninferrable_jump(const disasm_instruction_t * const instr)
{
    assert(instr);

    return ( (instr->decode.op == rv_op_jalr) &&
             (0 != instr->decode.rs1) )       ||
        (instr->decode.op == rv_op_c_jalr) ||
        (instr->decode.op == rv_op_c_jr);
}

static bool is_uninferrable_discon(const disasm_instruction_t * const instr)
{
    assert(instr);

    /*
     * Note: The exception reporting mechanism means it is not necessary
     * to include ECALL, EBREAK or C.EBREAK in this predicate
     */
    return is_uninferrable_jump(instr)        ||
        (instr->decode.op == rv_op_uret)   ||
        (instr->decode.op == rv_op_sret)   ||
        (instr->decode.op == rv_op_mret)   ||
        (instr->decode.op == rv_op_dret);
}

/*
 * Determine if instruction is a call
 * - excludes tail calls as they do not push an address onto the return stack
 */
static bool is_call(const disasm_instruction_t * const instr)
{
    assert(instr);
    return // jal x1
        ( (instr->decode.op == rv_op_jal)  &&
          (1 == instr->decode.rd) )        ||

        // jal x5
        ( (instr->decode.op == rv_op_jal)  &&
          (5 == instr->decode.rd) )        ||

        // jalr x1, rs where rs != x5
        ( (instr->decode.op == rv_op_jalr) &&
          ((1 == instr->decode.rd) && (5 != instr->decode.rs1)) ) ||

        // jalr x5, rs where rs != x1
        ( (instr->decode.op == rv_op_jalr) &&
          ((5 == instr->decode.rd) && (1 != instr->decode.rs1)) ) ||

        // c.jalr rs1 where rs1 != x5
        ( (instr->decode.op == rv_op_c_jalr) && (5 != instr->decode.rs1) ) ||

         // c.jal
        (instr->decode.op == rv_op_c_jal);
}

static bool is_return(const disasm_instruction_t *const instr)
{
  assert(instr);
  return ((instr->decode.op == rv_op_jalr) &&
          ((1 == instr->decode.rs1) || (5 == instr->decode.rs1)) &&
          (1 != instr->decode.rd) &&
          (5 != instr->decode.rd)) ||
      ((instr->decode.op == rv_op_c_jr) &&
       (1 == instr->decode.rs1));
}

static bool is_tail_call(const disasm_instruction_t *const instr)
{
  assert(instr);
  return // jal x0
      ((instr->decode.op == rv_op_jal) &&
       (0 == instr->decode.rd)) ||

      // c.j
      (instr->decode.op == rv_op_c_j) ||

      // jalr x0, rs where rs != x1 and rs != x5
      ((instr->decode.op == rv_op_jalr) &&
       (0 == instr->decode.rd) &&
       (1 != instr->decode.rs1) &&
       (5 != instr->decode.rs1)) ||

      // c.jr rs1 where rs1 != x1 and rs1 != x5
      ((instr->decode.op == rv_op_c_jr) &&
       (1 != instr->decode.rs1) &&
       (5 != instr->decode.rs1));
}

static bool is_co_routine_swap(const disasm_instruction_t *const instr)
{
  assert(instr);
  return // jalr x1 x5
      ((instr->decode.op == rv_op_jalr) &&
       (1 == instr->decode.rd) &&
       (5 == instr->decode.rs1)) ||

      // jalr x5 x1
      ((instr->decode.op == rv_op_jalr) &&
       (5 == instr->decode.rd) &&
       (1 == instr->decode.rs1)) ||

      // c.jalr x5
      ((instr->decode.op == rv_op_c_jalr) &&
       (5 == instr->decode.rd));
}

/*
 * Determine if instruction is a sequentially inferrable jump
 */
static bool is_sequential_jump(
    const disasm_instruction_t * const curr_instr,
    const disasm_instruction_t * const prev_instr)
{
    bool predicate = false;

    assert(curr_instr);
    assert(prev_instr);

    if (!is_uninferrable_jump(curr_instr))
        return false;

    if ( (prev_instr->decode.op == rv_op_auipc) ||
         (prev_instr->decode.op == rv_op_lui)   ||
         (prev_instr->decode.op == rv_op_c_lui) )
    {
        predicate = (curr_instr->decode.rs1 == prev_instr->decode.rd);
    }

    return predicate;
}

static bool is_exception_call(const disasm_instruction_t *const instr)
{
  assert(instr);
  return (instr->decode.op == rv_op_ecall) || (instr->decode.op == rv_op_ebreak);
}

static int was_prev_branch_taken(void)
{
  /*
   * result: -1 = Previous wasn't a branch
   * result:  0 = Branch not taken
   * result:  1 = Branch taken
   */

  int result = -1;

  if (iss_data[previous].is_branch)
  {
    uint64_t sequential_pc_change = iss_data[previous].address + iss_data[previous].inst_length;
    if (iss_data[current].address == sequential_pc_change)
    {
      assert(post_iss_data[previous].itype[0] == ITYPE_NONE);
      result = 0;
    }
    else
    {
      assert(post_iss_data[previous].itype[0] == ITYPE_NONE);
      result = 1;
    }
  }

  return result;
}

static bool assign_current_itype_value(const itype_t type)
{
  if (type == ITYPE_INVALID)
  {
    return false;
  }

  post_iss_data[current].itype[0] = type;

  return true;
}

static itype_t infer_itype(void)
{
  assert(config_parsed);

  itype_t ret_itype = ITYPE_INVALID;

  // Check current exception or interrupt
  if (iss_data[current].is_interrupt) {
      assert(ret_itype == ITYPE_INVALID);
      ret_itype = ITYPE_INTERRUPT;
      post_iss_data[current].cause = iss_data[current].exception_value;
      post_iss_data[current].tval = iss_data[current].trap_value;
  } else if (iss_data[current].is_exception) {
      assert(ret_itype == ITYPE_INVALID);
      ret_itype = ITYPE_EXCEPTION;
      post_iss_data[current].cause = iss_data[current].exception_value;
      post_iss_data[current].tval = iss_data[current].trap_value;
  }

  if (iss_data[previous].is_exception || iss_data[previous].is_interrupt)
  {
    if (iss_data[current].is_return)
    {
      assert(ret_itype == ITYPE_INVALID);
      ret_itype = ITYPE_EXCEPTION_OR_INTERRUPT_RETURN;
    }
  }

  if (!iss_data[current].is_exception && !iss_data[current].is_interrupt)
  {
    switch (config_data_s.itype_width_p) {
    case 3:
      if (iss_data[current].is_uninferable_jump)
      {
        assert(ret_itype == ITYPE_INVALID);
        ret_itype = ITYPE_UNINFERABLE_JUMP;
      } else {
        assert(ret_itype == ITYPE_INVALID);
        ret_itype = ITYPE_NONE;
      }
      break;

    case 4:
      if (iss_data[current].is_jump)
      {
        if (iss_data[current].is_uninferable_jump)
        {
          if (iss_data[current].is_call)
          {
            assert(ret_itype == ITYPE_INVALID);
            ret_itype = ITYPE_UNINFERABLE_CALL;
          }
          else if (iss_data[current].is_tail_call)
          {
            assert(ret_itype == ITYPE_INVALID);
            ret_itype = ITYPE_UNINFERABLE_TAIL_CALL;
          }
          else if (iss_data[current].is_co_routine_swap)
          {
            assert(ret_itype == ITYPE_INVALID);
            ret_itype = ITYPE_CO_ROUTINE_SWAP;
          }
          else if (iss_data[current].is_return)
          {
            assert(ret_itype == ITYPE_INVALID);
            ret_itype = ITYPE_RETURN;
          }
          else if (iss_data[current].is_other_jump)
          {
            assert(ret_itype == ITYPE_INVALID);
            ret_itype = ITYPE_OTHER_UNINFERABLE_JUMP;
          }
          else
            /* We shouldn't get here */
            assert(0);
        }
        else
        {
          assert(iss_data[current].is_inferable_jump);

          if (iss_data[current].is_call)
          {
            assert(ret_itype == ITYPE_INVALID);
            ret_itype = ITYPE_INFERABLE_CALL;
          }
          else if (iss_data[current].is_tail_call)
          {
            assert(ret_itype == ITYPE_INVALID);
            ret_itype = ITYPE_INFERABLE_TAIL_CALL;
          }
          else if (iss_data[current].is_other_jump)
          {
            assert(ret_itype == ITYPE_INVALID);
            ret_itype = ITYPE_OTHER_INFERABLE_JUMP;
          }
        }
      }
      break;

    default:
      fprintf(stderr, "Error: Illegal itype width %d\n", config_data_s.itype_width_p);
      exit(1);
      break;
    }
  }

  if (ret_itype == ITYPE_INVALID)
  {
    assert(ret_itype == ITYPE_INVALID);
    ret_itype = ITYPE_NONE;
    // There should not be any activity (is_branch is only used by the next cycle)
    assert(!iss_data[current].is_exception);
    assert(!iss_data[current].is_interrupt);
    assert(!iss_data[current].is_return);
    assert(!iss_data[current].is_jump);
    assert(!iss_data[current].is_inferable_jump);
    assert(!iss_data[current].is_uninferable_jump);
    assert(!iss_data[current].is_sequentially_inferable_jump);
    assert(!iss_data[current].is_call);
    assert(!iss_data[current].is_tail_call);
    assert(!iss_data[current].is_co_routine_swap);
    assert(!iss_data[current].is_other_jump);
  }

  if (config_data_s.itype_width_p == 3)
  {
    if (ret_itype > ITYPE_RESERVED)
    {
      printf("itype_width_p set to 3. itype value attempted to be set above 3 bits\n");
      return ITYPE_INVALID;
    }
  }

  assert(assign_current_itype_value(ret_itype));

  return ret_itype;
}


static itype_t infer_previous_itype(void)
{
  itype_t ret_itype = ITYPE_INVALID;
  bool previous_itype_infered = false;

  // Check previous branch status
  if (iss_data[previous].is_branch)
  {
    if (1 == was_prev_branch_taken())
    {
      previous_itype_infered = true;
      ret_itype = ITYPE_TAKEN_BRANCH;
    }
    else if (0 == was_prev_branch_taken())
    {
      previous_itype_infered = true;
      ret_itype = ITYPE_NONTAKEN_BRANCH;
    }

    assert(previous_itype_infered);
    post_iss_data[previous].itype[0] = ret_itype;
  }
  else
  {
    ret_itype = post_iss_data[previous].itype[0];
  }

  if (previous_itype_infered)
  {
    assert((ret_itype == ITYPE_NONTAKEN_BRANCH) || (ret_itype == ITYPE_TAKEN_BRANCH));
  }
  else
  {
    assert(ret_itype != ITYPE_INVALID);
  }
  return ret_itype;
}

static bool convert_iss_data(void)
{
  assert(config_parsed);

  disassemble_inst(iss_data[current].instruction, iss_data[current].address);

  post_iss_data[current].priv = iss_data[current].privilege;
  post_iss_data[current].iaddr[0] = iss_data[current].address;
  iss_data[current].inst_length = decoded_inst_s[current].length;
  if (iss_data[current].is_exception)
      /* These instructions deliberately raise exceptions so the instructions retire as well
         as raising an exception */
      post_iss_data[current].iretire[0] = is_exception_call(&decoded_inst_s[current]) ? 1 : 0;
  else
      post_iss_data[current].iretire[0] = 1;

  /* ilastsize is such that 2^ilastsize is the length of the instruction in half-words */
  uint8_t ilastsize = 0;
  switch (iss_data[current].inst_length) {
  case 2: ilastsize = 0; break;
  case 4: ilastsize = 1; break;
  case 6:
      perror("Error: Unable to encode 48-bit instruction in ilastsize");
      exit(EXIT_FAILURE);
  case 8: ilastsize = 2; break;
  default:
      perror("Error: Unknown instruction length");
      exit(EXIT_FAILURE);
  }
  post_iss_data[current].ilastsize[0] = ilastsize;

  // Check previous branch status
  infer_previous_itype();

  // Begin checking current instruction itype. is_branch only set to allow next instruction to
  // check the flag.
  iss_data[current].is_branch = is_branch(&decoded_inst_s[current]);

  iss_data[current].is_inferable_jump = is_inferrable_jump(&decoded_inst_s[current]);
  iss_data[current].is_uninferable_jump = is_uninferrable_discon(&decoded_inst_s[current]);
  if (config_data_s.sijump_p && iss_data[current].is_uninferable_jump)
  {
    iss_data[current].is_sequentially_inferable_jump = is_sequential_jump(&decoded_inst_s[current], &decoded_inst_s[previous]);

    if (iss_data[current].is_sequentially_inferable_jump)
    {
      iss_data[current].is_inferable_jump = true;
      iss_data[current].is_uninferable_jump = false;

      post_iss_data[current].sijump[0] = true;
    }
  }

  assert(!(iss_data[current].is_inferable_jump && iss_data[current].is_uninferable_jump));
  if (iss_data[current].is_inferable_jump || iss_data[current].is_uninferable_jump)
  {
    iss_data[current].is_jump = true;

    iss_data[current].is_call = is_call(&decoded_inst_s[current]);
    iss_data[current].is_tail_call = is_tail_call(&decoded_inst_s[current]);
    iss_data[current].is_co_routine_swap = is_co_routine_swap(&decoded_inst_s[current]);
    iss_data[current].is_return = is_return(&decoded_inst_s[current]);
    /* Anything else must be an "other" jump */
    iss_data[current].is_other_jump = !iss_data[current].is_call &&
        !iss_data[current].is_tail_call &&
        !iss_data[current].is_co_routine_swap &&
        !iss_data[current].is_return;
  }

  return (infer_itype() != ITYPE_INVALID);
}

static void write_encoder_input_line(char *out_line, FILE *out_fp, const post_iss_t *const post_iss_s)
{
  assert(config_parsed);

  assert(out_line);
  assert(out_fp);
  assert(post_iss_s);

  uint64_t chars_written = 0u;
  uint64_t chars_available = POST_ISS_MAX_OUTPUT_LINE_LEN;
  size_t n_retires = (size_t)config_data_s.retires_p;
  assert(n_retires > 0);

  for (size_t i = 0; i < n_retires; i++)
  {
    chars_written = snprintf(out_line, chars_available, "%d,", post_iss_s->itype[i]);
    chars_available -= chars_written;
    assert(chars_available < POST_ISS_MAX_OUTPUT_LINE_LEN);
    out_line += chars_written;
  }

  chars_written = snprintf(out_line, chars_available, "%d,%lx,%d,", post_iss_s->cause, post_iss_s->tval, post_iss_s->priv);
  chars_available -= chars_written;
  assert(chars_available < POST_ISS_MAX_OUTPUT_LINE_LEN);
  out_line += chars_written;

  for (size_t i = 0; i < n_retires; i++)
  {
    chars_written = snprintf(out_line, chars_available, "%lx,", post_iss_s->iaddr[i]);
    chars_available -= chars_written;
    assert(chars_available < POST_ISS_MAX_OUTPUT_LINE_LEN);
    out_line += chars_written;
  }

  if (!config_data_s.nocontext_p)
  {
    chars_written = snprintf(out_line, chars_available, "%d,", post_iss_s->context);
    chars_available -= chars_written;
    assert(chars_available < POST_ISS_MAX_OUTPUT_LINE_LEN);
    out_line += chars_written;
  }

  if (!config_data_s.notime_p)
  {
    chars_written = snprintf(out_line, chars_available, "%ld,", post_iss_s->time);
    chars_available -= chars_written;
    assert(chars_available < POST_ISS_MAX_OUTPUT_LINE_LEN);
    out_line += chars_written;
  }

  if (!config_data_s.nocontext_p)
  {
    chars_written = snprintf(out_line, chars_available, "%d,", post_iss_s->ctype);
    chars_available -= chars_written;
    assert(chars_available < POST_ISS_MAX_OUTPUT_LINE_LEN);
    out_line += chars_written;
  }

  if (config_data_s.sijump_p)
  {
    for (size_t i = 0; i < n_retires; i++)
    {
      chars_written = snprintf(out_line, chars_available, "%d,", post_iss_s->sijump[i]);
      chars_available -= chars_written;
      assert(chars_available < POST_ISS_MAX_OUTPUT_LINE_LEN);
      out_line += chars_written;
    }
  }

  for (size_t i = 0; i < n_retires; i++)
  {
    chars_written = snprintf(out_line, chars_available, "%d,", post_iss_s->iretire[i]);
    chars_available -= chars_written;
    assert(chars_available < POST_ISS_MAX_OUTPUT_LINE_LEN);
    out_line += chars_written;
  }

  for (size_t i = 0; i < n_retires; i++)
  {
    chars_written = snprintf(out_line, chars_available, "%d,", post_iss_s->ilastsize[i]);
    chars_available -= chars_written;
    assert(chars_available < POST_ISS_MAX_OUTPUT_LINE_LEN);
    out_line += chars_written;
  }

  out_line -= 1;
  *out_line = '\n';
  out_line += 1;
  *out_line = '\0';

  chars_written += 1;
  chars_available -= chars_written;
  assert(chars_available < POST_ISS_MAX_OUTPUT_LINE_LEN);

  assert(fputs(output_line_buf, out_fp) != EOF);
}

void set_rv_isa_32bit(const bool set_isa_32)
{
  if (set_isa_32)
  {
    isa = rv32;
  }
  else
  {
    isa = rv64;
  }
}

bool post_iss_parse_config(char *conf_file)
{
  assert(conf_file != NULL);
  assert(!config_parsed);

  config_parsed = parse_static_config_file(conf_file, &config_data_s);

  return config_parsed;
}

void process_iss_file(const char *const in_file)
{
  assert(config_parsed);

  FILE *in_fp = NULL;
  FILE *out_fp = NULL;
  char *line = NULL;
  size_t len = 0;
  ssize_t n_read = 0;
  iss_parse_result_t p_result = iss_parse_fail;
  static uint64_t line_idx = 0;

  in_fp = fopen(in_file, "r");
  if (in_fp == NULL)
  {
    fprintf(stderr, "Error opening file:%s\n", in_file);
    exit(EXIT_FAILURE);
  }

  char *output_file = generate_encoder_output_filename(in_file);
  out_fp = fopen(output_file, "w");
  if (out_fp == NULL)
  {
    fprintf(stderr, "Error opening output file:%s\n", output_file);
    exit(EXIT_FAILURE);
  }

  // Create header line
  generate_output_header(output_line_buf);
  assert(fputs(output_line_buf, out_fp) != EOF);

  // Init current and previous structs to hold parsed line data
  init_iss_content_array();

  // Init current and previous structs to hold decoded instructions
  init_te_decodoed_instruct_array();

  // Init current and previous structs to hold Post-ISS transformed data.
  init_post_iss_array();

  while ((n_read = getline(&line, &len, in_fp)) != -1)
  {
    p_result = parse_iss_line(line, &iss_data[current]);
    assert(p_result != iss_parse_fail);
    line_idx += p_result;

    if (p_result > iss_parse_header)
    {
      assert(convert_iss_data());

      if (line_idx > 1)
      {
        write_encoder_input_line(output_line_buf, out_fp, &post_iss_data[previous]);
      }

      swap_current_and_previous();

      init_current_data_structs();
    }
  }

  if (line != NULL)
      free(line);

  // Check previous branch status
  infer_previous_itype();

  write_encoder_input_line(output_line_buf, out_fp, &post_iss_data[previous]);
}

#ifdef CMAKE_TESTING_ENABLED

void post_iss_reset_test_config(void)
{
  init_static_config_struct(&config_data_s);
  config_parsed = false;
}

void post_iss_set_test_config(static_config_t *config_data_p)
{
  config_data_s = *config_data_p;
  config_parsed = true;
}

void testwrap_set_post_iss_header_struct(post_iss_header_t *header_p, const char *col_name, const uint64_t n_repeats, const bool is_last)
{
  set_post_iss_header_struct(header_p, col_name, n_repeats, is_last);
}

uint64_t testwrap_define_post_iss_header(post_iss_header_t header_p[])
{
  return define_post_iss_header(header_p);
}

void testwrap_generate_output_header(char *line)
{
  generate_output_header(line);
}

char *testwrap_generate_encoder_output_filename(const char *const input_filename)
{
   return generate_encoder_output_filename(input_filename);
}

void testwrap_swap_current_and_previous(uint8_t *current_val_p, uint8_t *previous_val_p)
{
  swap_current_and_previous();
  *current_val_p = current;
  *previous_val_p = previous;
}

void testwrap_init_iss_content_t(iss_content_t *const iss_content)
{
  init_iss_content_t(iss_content);
}

void testwrap_init_disasm_instruction_t(disasm_instruction_t *const dec_inst_s)
{
  init_disasm_instruction_t(dec_inst_s);
}

iss_parse_result_t testwrap_parse_iss_line(const char *const line, iss_content_t *const iss_content)
{
  return parse_iss_line(line, iss_content);
}

int testwrap_was_prev_branch_taken(bool previous_was_branch, uint64_t prev_address, uint8_t prev_inst_length, uint64_t current_address)
{
  init_iss_content_array();
  init_post_iss_array();

  iss_data[previous].is_branch = previous_was_branch;
  iss_data[previous].address = prev_address;
  iss_data[previous].inst_length = prev_inst_length;
  post_iss_data[previous].itype[0] = ITYPE_NONE;

  iss_data[current].address = current_address;

  return was_prev_branch_taken();
}

bool testwrap_assign_current_itype_value(const itype_t type, const itype_t current_itype)
{
  init_post_iss_array();
  post_iss_data[current].itype[0] = current_itype;

  return assign_current_itype_value(type);
}

static void helper_set_iss_data(iss_content_t *sink_iss_data, iss_content_t *source_iss_data)
{
  sink_iss_data->address = source_iss_data->address;
  sink_iss_data->instruction = source_iss_data->instruction;
  sink_iss_data->privilege = source_iss_data->privilege;
  sink_iss_data->is_exception = source_iss_data->is_exception;
  sink_iss_data->exception_value = source_iss_data->exception_value;
  sink_iss_data->trap_value = source_iss_data->trap_value;
  sink_iss_data->is_interrupt = source_iss_data->is_interrupt;
  sink_iss_data->inst_length = source_iss_data->inst_length;
  sink_iss_data->is_branch = source_iss_data->is_branch;
  sink_iss_data->is_return = source_iss_data->is_return;
  sink_iss_data->is_jump = source_iss_data->is_jump;
  sink_iss_data->is_inferable_jump = source_iss_data->is_inferable_jump;
  sink_iss_data->is_uninferable_jump = source_iss_data->is_uninferable_jump;
  sink_iss_data->is_sequentially_inferable_jump = source_iss_data->is_sequentially_inferable_jump;
  sink_iss_data->is_call = source_iss_data->is_call;
  sink_iss_data->is_tail_call = source_iss_data->is_tail_call;
  sink_iss_data->is_co_routine_swap = source_iss_data->is_co_routine_swap;
  sink_iss_data->is_other_jump = source_iss_data->is_other_jump;
}

itype_t testwrap_infer_itype(iss_content_t *current_iss_content, iss_content_t *previous_iss_content)
{
  assert(current_iss_content);

  init_iss_content_array();
  helper_set_iss_data(&iss_data[current], current_iss_content);

  if (previous_iss_content)
  {
    helper_set_iss_data(&iss_data[previous], previous_iss_content);
  }

  return infer_itype();
}

itype_t testwrap_infer_previous_itype(iss_content_t *current_iss_content, iss_content_t *previous_iss_content)
{
  assert(current_iss_content);
  assert(previous_iss_content);

  init_iss_content_array();
  helper_set_iss_data(&iss_data[current], current_iss_content);
  helper_set_iss_data(&iss_data[previous], previous_iss_content);

  post_iss_data[previous].itype[0] = ITYPE_NONE;

  return infer_previous_itype();
}

rv_isa testwrap_set_rv_isa_32bit(const bool set_isa_32)
{
  set_rv_isa_32bit(set_isa_32);
  return isa;
}

#endif
