/*
 * Copyright (c) 2019,2020 UltraSoC Technologies Limited
 * All rights reserved.
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
#include "decoder-algorithm-public.h"
#include "te-codec-utilities.h"


/*
 * evaluate the number of elements in an array
 */
#define elements_of(array)  (sizeof(array)/sizeof(*array))




/*
 * Fake up some default values that would be obtained through
 * "discovery", or means other than "te_inst" packets.
 */
static const te_discovery_response_t default_discovery_response =
{
    .call_counter_size = 9,     /* use a call-counter with a maximum of 512 calls */
    .return_stack_size = 0,     /* no real irstack on encoder, if using a call-counter */
    .iaddress_lsb = 1,          /* 1 == compressed instructions supported */
    .jump_target_cache_size = TE_CACHE_SIZE_P,
    .branch_prediction_size = TE_BPRED_SIZE_P,
};


/*
 * default run-time configuration "options" bits
 */
static const te_options_t default_support_options =
{
    .full_address = false,      /* use differential addresses */
    .implicit_return = false,   /* disable using return_stack[] */
    .implicit_exception = false,/* disable using implicit exception mode */
    .jump_target_cache = false, /* disable using jump_target[] */
    .branch_prediction = false, /* disable using a branch predictor */
};


/*
 * array of error messages used by unrecoverable_error()
 */
static const char * const error_messages[TE_ERROR_NUM_ERRORS] =
{
    [TE_ERROR_OKAY]                 = NULL, /* this is NOT an error condition! */
    [TE_ERROR_DEPLETED]             = "cannot resolve branch (branch-map depleted)!",
    [TE_ERROR_UNINFERRABLE]         = "unexpected uninferrable discontinuity",
    [TE_ERROR_BAD_FOLLOW]           = "follow_execution_path() has stop_at_last_branch=true and branches=0",
    [TE_ERROR_UNPROCESSED]          = "unprocessed branches",
    [TE_ERROR_IMPLICT_EXCEPTION]    = "implicit exception mode is not currently supported",
    [TE_ERROR_NOT_FORMAT3]          = "expecting trace to start with a format 3 packet",
};


/*
 * Process an unrecoverable error with the trace-decoder's algorithm.
 * This is indicative of a serious malfunction - this should never happen!
 *
 * This function prints a diagnostic, and it will call exit() to terminate.
 * If the parameter "instr" is not NULL, then it will also print the
 * disassembly line of the instruction ("instr") passed in.
 *
 * NOTE: this function will (by default) return to its caller!
 * However, any functions registered with atexit() will be called.
 *
 * That said, this source file (in toto) should assume that this
 * function *might* actually return, as some users may wish not to
 * call exit() directly here, and have higher functions detect that
 * decoder->error_code != TE_ERROR_OKAY, and process accordingly.
 * Thus, any callers of unrecoverable_error() should always assume
 * it *does* return, and return immediately to its caller, et. seq.
 */
static void unrecoverable_error(
    te_decoder_state_t * const decoder,
    const te_error_code_t error_code,
    const te_decoded_instruction_t * const instr)
{
    assert(decoder);
    assert(TE_ERROR_OKAY == decoder->error_code);
    assert(TE_ERROR_OKAY != error_code);
    assert(TE_ERROR_NUM_ERRORS > error_code);

    /* first, save the error code in the decoder structure */
    decoder->error_code = error_code;

    fprintf(stderr, "ERROR: %s\n", error_messages[error_code]);

    if (instr)
    {
        fprintf(stderr, "Whilst processing the following instruction:\n");
        fprintf(stderr, "%12" PRIx64 ":\t%s\n", instr->decode.pc, instr->line);
    }

    fflush(stderr);

    exit(1);    /* do not return ... bye bye */
}


/*
 * for the address given, find the raw binary value of the instruction at
 * that address (using the function decoder->get_instruction), and then use
 * the open-source riscv-disassembler library to decode, and then cache it.
 */
#define get_instr te_get_and_disassemble_instr  /* alias the function */
te_decoded_instruction_t * te_get_and_disassemble_instr(
    te_decoder_state_t * const decoder,
    const te_address_t address,
    te_decoded_instruction_t * const instr)
{
    const size_t slot = TE_SLOT_NUMBER(address);
    rv_inst instruction = 0;
    unsigned length;

    assert(decoder);
    assert(decoder->get_instruction);
    assert(instr);
    assert(TE_SENTINEL_BAD_ADDRESS != address);

    decoder->num_gets++;        /* update statistics */

    /*
     * if the address matches the decoded one passed in ...
     * ... then just return it! Nothing to do this time!
     */
    if ( (instr->decode.pc == address) )
    {
        decoder->num_same++;        /* update statistics */
        return instr;       /* referenced data is unchanged */
    }

    /* is "address" currently in our decoded cache ? */
    if (decoder->decoded_cache[slot].decode.pc == address)
    {
        decoder->num_hits++;        /* update statistics */
        /* copy, and return the cached decode */
        *instr = decoder->decoded_cache[slot];
        return instr;       /* referenced data is updated */
    }

    /* otherwise, we need to do a bit of disassembly work ... */

    /* first, get the raw instruction (and its length), from its address */
    length = (decoder->get_instruction)(
        decoder->user_data,
        address,
        &instruction);

    assert( (4 == length) ||
            (2 == length) );

    /* cache the length of the instruction, for instruction_size() */
    instr->length = length;

    /*
     * Use the modified riscv-disassembler open-source library to decode
     * the instruction. This repository is available from:
     *
     * https://github.com/ultrasoc/riscv-disassembler/tree/ultrasoc
     *
     * Note: predicates in this code assumes that pseudo-instructions
     * are not lifted e.g. decode is not "ret", but "jalr x0,0(x1)".
     */
    (void)disasm_inst_adv(
        &instr->decode,
        instr->line,
        sizeof(instr->line) - 1,
        decoder->isa,
        address,
        instruction,
        false);     /* false: do not lift pseudo-instructions */

    /*
     * If it is a custom instruction, then we will want to
     * use a different disassembled text line, and possibly
     * overwrite some of the fields in the decoded state.
     * If custom instructions are supported, then process
     * any decoded properties of them here ...
     *
     * Note: decoder->do_custom_instruction may be NULL, in which
     * case there must not be any custom instructions.
     *
     * Note: both 'address' and 'instruction' are passed in
     * 'instr', as 'instr->decode.pc' and 'instr->decode.inst'.
     */
    if (decoder->do_custom_instruction)
    {
        (decoder->do_custom_instruction)(
            decoder->user_data,
            instr);
    }

    /* save the freshly decoded instruction in the decoded cache */
    decoder->decoded_cache[slot] = *instr;

    /*
     * finally, return the pointer to te_decoded_instruction_t passed in, whose
     * referenced data will have been updated (in situ), and
     * added to the decoded_cache[] cache.
     */
    return instr;
}


/*
 * Returns the size of the instruction in bytes
 * Only safe to be called after get_instr() with instr
 */
static unsigned instruction_size(
    const te_decoded_instruction_t * const instr)
{
    assert(instr);

    return instr->length;
}


/*
 * Note, this function does not calculate nor even update the PC.
 * It is merely a single control point that should be called
 * each time the PC is updated, so we can inspect, check and record
 * each and every transition of the PC in a consistent manner.
 * This helps with checking the correctness of the decoder.
 *
 * Ultimately, the main purpose of this function is to call-back the
 * function-pointer decoder->advance_decoded_pc, to disseminate
 * the new value of the PC.
 */
static void disseminate_pc(
    te_decoder_state_t * const decoder)
{
    te_decoded_instruction_t instr = { .decode.pc = TE_SENTINEL_BAD_ADDRESS };

    assert(decoder);

    /* do some sanity checks ... just in case! */
    assert(TE_SENTINEL_BAD_ADDRESS != decoder->pc);
    if (decoder->statistics.num_instructions)
    {
        /* it is NOT the first transition */
        assert(TE_SENTINEL_BAD_ADDRESS != decoder->last_pc);
    }
    else
    {
        /* it is the FIRST transition */
        assert(TE_SENTINEL_BAD_ADDRESS == decoder->last_pc);
    }

    /* decode & disassemble the instruction at the new PC */
    (void)get_instr(decoder, decoder->pc, &instr);

    /* optionally show the transition & instruction at the new PC */
    if ((decoder->debug_stream) && (decoder->debug_flags & TE_DEBUG_PC_TRANSITIONS))
    {
        fprintf(decoder->debug_stream,
            "%s\t[%2" PRIu64 "] set_pc %8" PRIx64 " -> %8" PRIx64 ":\t%s\n",
            (decoder->pc == decoder->last_sent_addr) ? "---->" : "",
            decoder->branches,
            decoder->last_pc,
            decoder->pc,
            instr.line);
    }

    /*
     * notify the user that the PC has been updated
     *
     * Note: decoder->advance_decoded_pc may be NULL.
     */
    if (decoder->advance_decoded_pc)
    {
        (decoder->advance_decoded_pc)(
            decoder->user_data,
            decoder->last_pc,
            decoder->pc,
            &instr);
    }

    /* advance the count of PC transitions */
    decoder->statistics.num_instructions++;
}


/*
 * Determine if current instruction is a branch
 */
static bool is_branch(
    const te_decoded_instruction_t * const instr)
{
    bool predicate = false;

    assert(instr);

    if ( (instr->decode.op == rv_op_beq)    ||
         (instr->decode.op == rv_op_bne)    ||
         (instr->decode.op == rv_op_blt)    ||
         (instr->decode.op == rv_op_bge)    ||
         (instr->decode.op == rv_op_bltu)   ||
         (instr->decode.op == rv_op_bgeu)   ||
         (instr->decode.op == rv_op_c_beqz) ||
         (instr->decode.op == rv_op_c_bnez) )
    {
        predicate = true;
    }

    return predicate;
}


/*
 * Determine if current instruction is a branch, adjust the branch
 * count/map, and return the "taken" status
 *
 * If an unrecoverable error occurs, this function will immeditely
 * return false, if the function unrecoverable_error() returns.
 */
static bool is_taken_branch(
    te_decoder_state_t * const decoder,
    const te_decoded_instruction_t * const instr)
{
    bool taken = false;     /* assume branch not taken */
    size_t bpred_index = 0;
    bool predicted_outcome = false;
    const char * source = NULL;

    assert(decoder);
    assert(instr);

    if (!is_branch(instr))
    {
        return false;
    }

    if (0 == decoder->branches)
    {
        unrecoverable_error(decoder, TE_ERROR_DEPLETED, instr);
        return false;       /* return immediately if an unrecoverable error */
    }

    /* this branch will be processed, decrement remaining branches */
    decoder->branches--;

    /*
     * retrieve the prediction from the branch predictor,
     * if it is enabled.
     */
    if (decoder->options.branch_prediction)
    {
        /* find the (direct-mapped) index into the branch predictor table */
        bpred_index = te_get_bpred_index(instr->decode.pc, &decoder->discovery_response);
        /* retrieve the extant state from the branch predictor table */
        const te_bpred_state_t old_state =
            (te_bpred_state_t)(decoder->bpred.table[bpred_index]);
        /* decode the predicted state */
        predicted_outcome = !!(old_state & 0x2u);
    }

    /*
     * work out if the current branch will be taken or not ...
     *
     * This can come from several different sources!
     * e.g. if we are using a branch-count, then use that and not
     * the branch-map to determine if the branch is taken or not.
     */
    assert(!decoder->bpred.use_bmap_first || !decoder->bpred.miss_predict_carry_in);
    if (decoder->bpred.use_bmap_first)
    {
        /* the branch_map still has one valid bit to be consumed */
        taken = !(decoder->branch_map & 1);  /* bit [0] */
        decoder->branch_map >>= 1;   /* right-shift one bit */
        decoder->bpred.use_bmap_first = false;
        source = "bmap[0]";
    }
    else if (decoder->bpred.miss_predict_carry_in)
    {
        /* this branch is a miss-predict from the previous packet */
        taken = !predicted_outcome; /* miss-prediction */
        decoder->bpred.miss_predict_carry_in = false;
        source = "carry-in";
    }
    else if (decoder->bpred.correct_predictions)
    {
        /* use the branch predictor for the next branch */
        taken = predicted_outcome;  /* correct prediction */
        source = "bpred";
    }
    else
    {
        /* use and then shift the branch-map[] */
        taken = !(decoder->branch_map & 1);  /* bit [0] */
        decoder->branch_map >>= 1;   /* right-shift one bit */
        source = "bmap";
    }

    /*
     * update the branch prediction lookup table, for the branch predictor,
     * if it is enabled.
     */
    if (decoder->options.branch_prediction)
    {
        /* retrieve the extant state from the branch predictor table */
        const te_bpred_state_t old_state =
            (te_bpred_state_t)(decoder->bpred.table[bpred_index]);
        /* calculate the next value of the branch predictor state */
        const te_bpred_state_t new_state = te_next_bpred_state(old_state, taken);

        /* optionally, print out what we have done */
        if ( (decoder->debug_stream) &&
             (decoder->debug_flags & TE_DEBUG_BRANCH_PREDICTION) )
        {
            const bool previous_outcome = !!(old_state & 0x1u);
            fprintf(decoder->debug_stream,
                "bpred-%u: %" PRIx64 ", bpred_table[%02" PRIx64 "] = %d%d -> %d%d,"
                "  branches = %2" PRIu64 ",  %-8s  %-9s  %s\n",
                ++decoder->bpred.serial,
                instr->decode.pc,
                bpred_index,
                (predicted_outcome) ? 1 : 0,    /* MSB */
                (previous_outcome)  ? 1 : 0,    /* LSB */
                (new_state & 0x2u)  ? 1 : 0,    /* MSB */
                (new_state & 0x1u)  ? 1 : 0,    /* LSB */
                decoder->branches,
                source,
                taken ? "TAKEN" : "not taken",
                (predicted_outcome == taken) ? "CORRECTLY PREDICATED" : "miss-predicted");
        }

        /* finally update the lookup table with the new state */
        decoder->bpred.table[bpred_index] = (uint8_t)new_state;
    }

    return taken;
}


/*
 * Determine if instruction is an inferrable jump
 */
static bool is_inferrable_jump(
    const te_decoded_instruction_t * const instr)
{
    bool predicate = false;

    assert(instr);

    if ( (instr->decode.op == rv_op_jal)    ||
         (instr->decode.op == rv_op_c_jal)  ||
         (instr->decode.op == rv_op_c_j)    ||
         ( (instr->decode.op == rv_op_jalr) &&
           (0 == instr->decode.rs1) ) )
    {
        predicate = true;
    }

    return predicate;
}


/*
 * Determine if instruction is an uninferrable jump
 */
static bool is_uninferrable_jump(
    const te_decoded_instruction_t * const instr)
{
    bool predicate = false;

    assert(instr);

    if ( ( (instr->decode.op == rv_op_jalr) &&
           (0 != instr->decode.rs1) )       ||
         (instr->decode.op == rv_op_c_jalr) ||
         (instr->decode.op == rv_op_c_jr) )
    {
        predicate = true;
    }

    return predicate;
}


/*
 * Determine if instruction is an uninferrable discontinuity
 */
static bool is_uninferrable_discon(
    const te_decoded_instruction_t * const instr)
{
    bool predicate = false;

    assert(instr);

    /*
     * Note: The exception reporting mechanism means it is not necessary
     * to include ECALL, EBREAK or C.EBREAK in this predicate
     */
    if ( is_uninferrable_jump(instr)        ||
         (instr->decode.op == rv_op_uret)   ||
         (instr->decode.op == rv_op_sret)   ||
         (instr->decode.op == rv_op_mret)   ||
         (instr->decode.op == rv_op_dret) )
    {
        predicate = true;
    }

    return predicate;
}


/*
 * Determine if instruction is a sequentially inferrable jump
 */
static bool is_sequential_jump(
    te_decoder_state_t * const decoder,
    const te_decoded_instruction_t * const instr,
    const te_address_t prev_addr)
{
    te_decoded_instruction_t prev_instr = { .decode.pc = TE_SENTINEL_BAD_ADDRESS };
    bool predicate = false;

    assert(decoder);
    assert(instr);

    if (!is_uninferrable_jump(instr))
    {
        return false;
    }

    (void)get_instr(decoder, prev_addr, &prev_instr);

    if ( (prev_instr.decode.op == rv_op_auipc) ||
         (prev_instr.decode.op == rv_op_lui)   ||
         (prev_instr.decode.op == rv_op_c_lui) )
    {
        predicate = (instr->decode.rs1 == prev_instr.decode.rd);
    }

    return predicate;
}


/*
 * Find the target of a sequentially inferrable jump
 */
static te_address_t sequential_jump_target(
    te_decoder_state_t * const decoder,
    const te_address_t addr,
    const te_address_t prev_addr)
{
    te_decoded_instruction_t instr      = { .decode.pc = TE_SENTINEL_BAD_ADDRESS };
    te_decoded_instruction_t prev_instr = { .decode.pc = TE_SENTINEL_BAD_ADDRESS };
    te_address_t target = 0;

    assert(decoder);

    (void)get_instr(decoder, addr, &instr);
    (void)get_instr(decoder, prev_addr, &prev_instr);

    if (prev_instr.decode.op == rv_op_auipc)
    {
        target = prev_addr;
    }

    const int64_t imm = prev_instr.decode.imm;
    target += (te_address_t)imm;

    if (instr.decode.op == rv_op_jalr)
    {
        const int64_t imm2 = instr.decode.imm;
        target += (te_address_t)imm2;
    }

    return target;
}


/*
 * Determine if instruction is a call
 * - excludes tail calls as they do not push an address onto the return stack
 */
static bool is_call(
    const te_decoded_instruction_t * const instr)
{
    bool predicate = false;

    assert(instr);

    if ( ( (instr->decode.op == rv_op_jalr) &&
           (1 == instr->decode.rd) )        ||
         (instr->decode.op == rv_op_c_jalr) ||
         ( (instr->decode.op == rv_op_jal)  &&
           (1 == instr->decode.rd) )        ||
         (instr->decode.op == rv_op_c_jal) )
    {
        predicate = true;
    }

    return predicate;
}


/*
 * Determine if instruction return address can be implicitly inferred
 */
static bool is_implicit_return(
    const te_decoder_state_t * const decoder,
    const te_decoded_instruction_t * const instr,
    const te_inst_t * const te_inst)
{
    bool predicate = false;
    assert(decoder);
    assert(instr);
    assert(te_inst);

    if (decoder->options.implicit_return == 0)
    {
        return false;   /* Implicit return mode is disabled */
    }

    /*
     * In the following code the value of "te_inst->irfail" is
     * not the value of the irfail bit physically transmitted
     * in the te_inst packet. Instead it is a logical XOR
     * that indicates if the irfail bit physically transmitted
     * was different from the previously transmitted bit.
     * See comment in the definition of "te_inst_t" for details.
     */
    if ( ( (instr->decode.op == rv_op_jalr) &&
           (1 == instr->decode.rs1)         &&
           (0 == instr->decode.rd) )        ||
         ( (instr->decode.op == rv_op_c_jr) &&
           (1 == instr->decode.rs1) ) )
    {
        if ( (te_inst->irfail) &&
             (te_inst->irdepth == decoder->irstack_depth) )
        {
            /* implicit return address prediction failed here */
            predicate = false;
        }
        else
        {
            /* return true if the irstack is not empty */
            predicate = (decoder->irstack_depth > 0);
        }
    }

    return predicate;
}


/*
 * Push address onto the implicit return stack
 */
static void push_return_stack(
    te_decoder_state_t * const decoder,
    const te_address_t address)
{
    te_decoded_instruction_t instr = { .decode.pc = TE_SENTINEL_BAD_ADDRESS };
    te_address_t link_reg = address;
    size_t i;

    assert(decoder);

    if (!decoder->options.implicit_return)
    {
        return;     /* Implicit return mode is disabled */
    }

    const size_t irstack_depth_max =
        (decoder->discovery_response.return_stack_size) ?
            (size_t)1 << decoder->discovery_response.return_stack_size :
            (size_t)1 << decoder->discovery_response.call_counter_size;
    assert(decoder->irstack_depth <= irstack_depth_max);
    assert(irstack_depth_max <= TE_MAX_IRSTACK_DEPTH);

    if (irstack_depth_max == decoder->irstack_depth)
    {
        /* Delete oldest entry from irstack to make room for new entry added below */
        decoder->irstack_depth--;
        for (i = 0; i < decoder->irstack_depth; i++)
        {
            decoder->return_stack[i] = decoder->return_stack[i+1];
        }
    }

    /* link register is address of next spatial instruction */
    (void)get_instr(decoder, address, &instr);
    link_reg += instruction_size(&instr);

    /* optionally show what we will push onto the irstack */
    if ((decoder->debug_stream) && (decoder->debug_flags & TE_DEBUG_IMPLICIT_RETURN))
    {
        fprintf(decoder->debug_stream,
            "irstack: pushed [%3" PRIu64 "] <-- %08" PRIx64 "\n",
            decoder->irstack_depth,
            link_reg);
    }

    /* push link register to top of the irstack */
    decoder->return_stack[decoder->irstack_depth] = link_reg;
    decoder->irstack_depth++;
}


/*
 * Pop address from the implicit return stack
 */
static te_address_t pop_return_stack(
    te_decoder_state_t * const decoder)
{
    assert(decoder);

    /*
     * Note: this function is not called if irstack_depth is 0,
     * so no need to check for underflow
     */
    decoder->irstack_depth--;

    const te_address_t link_reg = decoder->return_stack[decoder->irstack_depth];

    /* optionally show what we will pop from the irstack */
    if ((decoder->debug_stream) && (decoder->debug_flags & TE_DEBUG_IMPLICIT_RETURN))
    {
        fprintf(decoder->debug_stream,
            "irstack: popped [%3" PRIu64 "] --> %08" PRIx64 "\n",
            decoder->irstack_depth,
            link_reg);
    }

    return link_reg;
}


/*
 * Compute the next PC
 *
 * Returns true if it is an uninferrable discontinuity,
 * and a return address was NOT popped from the irstack.
 * i.e. the parameter "address" is assigned to the PC.
 * Otherwise this function returns false.
 *
 * If an unrecoverable error occurs, this function will immeditely
 * return false, if the function unrecoverable_error() returns.
 */
static bool next_pc(
    te_decoder_state_t * const decoder,
    const te_address_t address,
    const te_inst_t * const te_inst)
{
    bool stop_here = false;

    assert(decoder);
    assert(te_inst);

    const te_address_t this_pc = decoder->pc;
    te_decoded_instruction_t instr = { .decode.pc = TE_SENTINEL_BAD_ADDRESS };

    (void)get_instr(decoder, decoder->pc, &instr);

    if (is_branch(&instr))
    {
        /* update counter with number of branch instructions */
        decoder->statistics.num_branches++;
    }

    if (is_inferrable_jump(&instr))
    {
        const int64_t imm = instr.decode.imm;
        decoder->pc += (te_address_t)imm;
    }
    else if (is_sequential_jump(decoder, &instr, decoder->last_pc))
    {
        /* lui/auipc followed by jump using same register */
        decoder->pc = sequential_jump_target(decoder, decoder->pc, decoder->last_pc);
    }
    else if (is_implicit_return(decoder, &instr, te_inst))
    {
        decoder->pc = pop_return_stack(decoder);
    }
    else if (is_uninferrable_discon(&instr))
    {
        if (decoder->stop_at_last_branch)
        {
            unrecoverable_error(decoder, TE_ERROR_UNINFERRABLE, &instr);
            return false;    /* return immediately if an unrecoverable error */
        }
        else
        {
          decoder->pc = address;
          stop_here = true;
        }
        /* update counter with number of unpredicted discontinuities */
        decoder->statistics.num_updiscons++;
    }
    else if (is_taken_branch(decoder, &instr))
    {
        const int64_t imm = instr.decode.imm;
        decoder->pc += (te_address_t)imm;
        /* update counter with number of taken branches */
        decoder->statistics.num_taken++;
    }
    else
    {
        /*
         * Note: is_taken_branch() can call unrecoverable_error(),
         * returning false if unrecoverable_error() returns.
         */
        if (TE_ERROR_OKAY != decoder->error_code)
        {
            return false; /* return immediately if an unrecoverable error */
        }
        decoder->pc += instruction_size(&instr);
    }

    if (is_call(&instr))
    {
        push_return_stack(decoder, this_pc);
        /* update counter with number of function calls */
        decoder->statistics.num_calls++;
    }

    decoder->last_pc = this_pc;
    disseminate_pc(decoder);

    return stop_here;
}


/*
 * Follow execution path to reported address
 *
 * If an unrecoverable error occurs, this function will immeditely
 * return, if the function unrecoverable_error() returns.
 */
static void follow_execution_path(
    te_decoder_state_t * const decoder,
    const te_address_t address,
    const te_inst_t * const te_inst)
{
    assert(decoder);

    te_address_t previous_address = decoder->pc;
    te_decoded_instruction_t instr = { .decode.pc = TE_SENTINEL_BAD_ADDRESS };

    assert(te_inst);

    (void)get_instr(decoder, decoder->pc, &instr);

    if ((decoder->debug_stream) && (decoder->debug_flags & TE_DEBUG_FOLLOW_PATH))
    {
        fprintf(decoder->debug_stream,
            "entered %s() with format = %u, pc = 0x%" PRIx64 ", and address = 0x%" PRIx64 "\n",
            __func__, te_inst->format, decoder->pc, address);
    }

    while (true)
    {
        if ( (decoder->stop_at_last_branch) &&
             (0 == decoder->branches) )
        {
            unrecoverable_error(decoder, TE_ERROR_BAD_FOLLOW, &instr);
            return; /* return immediately if an unrecoverable error */
        }

        if (decoder->inferred_address)
        {
            /*
             * iterate again from previously reported address to find second occurrence
             */
            const bool stop_here = next_pc(decoder, previous_address, te_inst);
            /*
             * Note: next_pc() can call unrecoverable_error(),
             * returning false if unrecoverable_error() returns.
             */
            if (TE_ERROR_OKAY != decoder->error_code)
            {
                return; /* return immediately if an unrecoverable error */
            }
            (void)get_instr(decoder, decoder->pc, &instr);
            if (stop_here)
            {
                decoder->inferred_address = false;
            }
        }
        else
        {
            const bool stop_here = next_pc(decoder, address, te_inst);
            /*
             * Note: next_pc() can call unrecoverable_error(),
             * returning false if unrecoverable_error() returns.
             */
            if (TE_ERROR_OKAY != decoder->error_code)
            {
                return; /* return immediately if an unrecoverable error */
            }
            (void)get_instr(decoder, decoder->pc, &instr);
            if ( (1 == decoder->branches)                             &&
                 (is_branch(get_instr(decoder, decoder->pc, &instr))) &&
                 (decoder->stop_at_last_branch) )
            {
                /*
                 * Reached final branch - stop here (do not follow to next instruction
                 * as we do not yet know whether it retires)
                 */
                decoder->stop_at_last_branch = false;
                return;
            }
            if (stop_here)
            {
                /*
                 * Reached reported address following an uninferrable discontinuity - stop here
                 */
                if (decoder->branches > (is_branch(get_instr(decoder, decoder->pc, &instr)) ? 1 : 0))
                {
                    /*
                     * Check all branches processed (except 1 if this instruction is a branch)
                     */
                    unrecoverable_error(decoder, TE_ERROR_UNPROCESSED, &instr);
                    return; /* return immediately if an unrecoverable error */
                }
                return;
            }
            /*
             * In the following code the value of "te_inst->notify" is
             * not the value of the notify bit physically transmitted
             * in the te_inst packet. Instead it is a logical XOR
             * that indicates if the notify bit physically transmitted
             * was different from the previously transmitted bit.
             * See comment in the definition of "te_inst_t" for details.
             */
            if ( (TE_INST_FORMAT_3_SYNC != te_inst->format)     &&
                 (decoder->pc == address)                       &&
                 (!decoder->stop_at_last_branch)                &&
                 (te_inst->notify)                              &&
                 (decoder->branches == (is_branch(get_instr(decoder, decoder->pc, &instr)) ? 1 : 0)) )
            {
                /*
                 * All branches processed, and reached reported address due
                 * to notification, and not as an uninferrable jump target
                 */
                return;
            }
            /*
             * In the following code the value of "te_inst->updiscon" is
             * not the value of the updiscon bit physically transmitted
             * in the te_inst packet. Instead it is a logical XOR
             * that indicates if the updiscon bit physically transmitted
             * was different from the previously transmitted bit.
             * See comment in the definition of "te_inst_t" for details.
             */
            if ( (TE_INST_FORMAT_3_SYNC != te_inst->format)     &&
                 (decoder->pc == address)                       &&
                 (!decoder->stop_at_last_branch)                &&
                 (!te_inst->updiscon)                           &&
                 (decoder->branches == (is_branch(get_instr(decoder, decoder->pc, &instr)) ? 1 : 0)) )
            {
                /*
                 * All branches processed, and reached reported address, but not as an
                 * uninferrable jump target. Stop here for now, though flag indicates
                 * this may not be final retired instruction
                 */
                decoder->inferred_address = true;
                return;
            }
            if ( (TE_INST_FORMAT_3_SYNC == te_inst->format)     &&
                 (decoder->pc == address)                       &&
                 (decoder->branches == (is_branch(get_instr(decoder, decoder->pc, &instr)) ? 1 : 0)) )
            {
                /* All branches processed, and reached reported address */
                return;
            }
        }
    }
}


#define PRINT_CHANGES_FLAG(option)                              \
do                                                              \
{                                                               \
    if (decoder->options.option != support->options.option)     \
    {                                                           \
        fprintf(                                                \
            decoder->debug_stream,                              \
            "info: configuration of %s changed: %s -> %s\n",    \
            #option,                                            \
            decoder->options.option ? "true" : "false",         \
            support->options.option ? "true" : "false");        \
    }                                                           \
} while (0)
#define PRINT_CHANGES_FIELD(s_option,d_option)                  \
do                                                              \
{                                                               \
    if (decoder->d_option != support->s_option)                 \
    {                                                           \
        fprintf(                                                \
            decoder->debug_stream,                              \
            "info: configuration of %s changed: %u -> %u\n",    \
            #s_option,                                          \
            decoder->d_option,                                  \
            support->s_option);                                 \
    }                                                           \
} while (0)


/*
 * Process a single te_inst synchronization support packet.
 * Called each time a support packet is received.
 *
 * If an unrecoverable error occurs, this function will immeditely
 * return, if the function unrecoverable_error() returns.
 */
static void process_support(
    te_decoder_state_t * const decoder,
    const te_inst_t * const te_inst)
{
    assert(decoder);
    assert(te_inst);
    const te_support_t * const support = &te_inst->support;

    /*
     * If the current te_inst support packet will change any of the run-time
     * configuration options, and we have a valid debug stream, then
     * append to this stream details of which options are being changed.
     */
    if (decoder->debug_stream)
    {
        /* single-bit run-time configuration options */
        PRINT_CHANGES_FLAG(implicit_return);
        PRINT_CHANGES_FLAG(implicit_exception);
        PRINT_CHANGES_FLAG(full_address);
        PRINT_CHANGES_FLAG(jump_target_cache);
        PRINT_CHANGES_FLAG(branch_prediction);

        /* multi-bit run-time configuration options */
        PRINT_CHANGES_FIELD(encoder_mode, encoder_mode);
    }

    /*
     * Copy the latest set of "options" into the decoder's state.
     * This will update the "live" set of run-time configuration
     * options that the trace-decoder will now use.
     */
    decoder->options = support->options;
    decoder->encoder_mode = support->encoder_mode;

    if (decoder->options.implicit_exception)
    {
        /* TODO: support the implicit exception mode */
        unrecoverable_error(decoder, TE_ERROR_IMPLICT_EXCEPTION, NULL);
        return; /* return immediately if an unrecoverable error */
    }

    if ( (TE_QUAL_STATUS_ENDED_UPD == support->qual_status) ||
         (TE_QUAL_STATUS_ENDED_REP == support->qual_status) )
    {
        /* Trace ended, so get ready to start again */
        decoder->start_of_trace = true;
    }

    if ( (TE_QUAL_STATUS_ENDED_UPD == support->qual_status) &&
         (decoder->inferred_address) )
    {
        const te_address_t previous_address = decoder->pc;
        decoder->inferred_address = false;
        while (true)
        {
            const bool stop_here = next_pc(decoder, previous_address, te_inst);
            /*
             * Note: next_pc() can call unrecoverable_error(),
             * returning false if unrecoverable_error() returns.
             */
            if (TE_ERROR_OKAY != decoder->error_code)
            {
                return; /* return immediately if an unrecoverable error */
            }
            if (stop_here)
            {
                return;
            }
        }
    }
}


/*
 * Process a single te_inst packet.
 * Called each time a te_inst packet is received.
 *
 * If an unrecoverable error occurs, this function will immeditely
 * return, if the function unrecoverable_error() returns.
 */
void te_process_te_inst(
    te_decoder_state_t * const decoder,
    const te_inst_t * const te_inst)
{
    te_decoded_instruction_t instr = { .decode.pc = TE_SENTINEL_BAD_ADDRESS };

    assert(decoder);
    assert(te_inst);

    /*
     * The caller of this function is expected to set the field
     * "with_address" in the structure pointed to by te_inst.
     * However, as a "sanity check", it is compared here against
     * what it ought to be, given the values of the other fields.
     */
    switch (te_inst->format)
    {
        case TE_INST_FORMAT_0_EXTN:
            if (TE_INST_EXTN_BRANCH_PREDICTOR == te_inst->extension)
            {
                assert( (TE_BRANCH_FMT_00_NO_ADDR != te_inst->u.bpred.branch_fmt) == te_inst->with_address);
            }
            break;

        case TE_INST_FORMAT_1_DIFF:
            assert(te_inst->with_address == !!te_inst->branches);
            break;

        case TE_INST_FORMAT_2_ADDR:
            assert(te_inst->with_address);
            break;

        case TE_INST_FORMAT_3_SYNC:
            if ( (TE_INST_SUBFORMAT_START == te_inst->subformat) ||
                 (TE_INST_SUBFORMAT_EXCEPTION == te_inst->subformat) )
            {
                assert(te_inst->with_address);
            }
            else
            {
                assert(!te_inst->with_address);
            }
            break;

        default:
            assert(!"Invalid packet format");
    }

    /*
     * update counters for each new te_inst packet that is received
     * for both the format, and the sub-format if it is a format 3.
     */
    decoder->statistics.num_format[te_inst->format]++;
    if (TE_INST_FORMAT_3_SYNC == te_inst->format)
    {
        decoder->statistics.num_subformat[te_inst->subformat]++;
    }

    if (TE_INST_FORMAT_3_SYNC == te_inst->format)
    {
        decoder->non_sync_packets = 0;

        /* is it a te_inst synchronization support packet ? */
        if (TE_INST_SUBFORMAT_SUPPORT == te_inst->subformat)
        {
            process_support(decoder, te_inst);
            /* Note: process_support() can call unrecoverable_error() */
            return; /* all done ... nothing more to do */
        }

        /* is it a te_inst synchronization context packet ? */
        if (TE_INST_SUBFORMAT_CONTEXT == te_inst->subformat)
        {
            return; /* all done ... nothing more to do */
        }

        /* is it a te_inst synchronization exception packet ? */
        if (TE_INST_SUBFORMAT_EXCEPTION == te_inst->subformat)
        {
            /* update counter with number of exceptions */
            decoder->statistics.num_exceptions++;

            if ( (decoder->debug_stream) &&
                 (decoder->debug_flags & TE_DEBUG_EXCEPTIONS) )
            {
                /*
                 * get details about the most recent successfully retired
                 * instruction ... that should be at decoder->pc.
                 */
                (void)te_get_and_disassemble_instr(decoder, decoder->pc, &instr);

                /*
                 * Here "address" is the instruction address that
                 * raised an exception. Which ought to be the first
                 * instruction spatially following the most recent
                 * reconstructed successfully retired instruction.
                 */
                const te_address_t address = decoder->pc + instr.length;

                /* get details about the instruction that raised an exception */
                (void)te_get_and_disassemble_instr(decoder, address, &instr);

                /* print out the instruction that raised an exception */
                fprintf(decoder->debug_stream,
                    "ECAUSE=%-2u [%" PRIu64 "]\t{%" PRIu64 "}\t%8" PRIx64 ":\t%s\n",
                    te_inst->ecause,
                    decoder->statistics.num_exceptions,
                    decoder->statistics.num_instructions,
                    address,
                    instr.line);
            }
        }

        /* copy any common fields from the te_inst packet */
        decoder->inferred_address = false;
        decoder->last_sent_addr = (te_inst->address << decoder->discovery_response.iaddress_lsb);
        decoder->privilege = te_inst->privilege;

        if ( (TE_INST_SUBFORMAT_EXCEPTION == te_inst->subformat) ||
             (decoder->start_of_trace) )
        {
            /* expunge any pending branches */
            decoder->branches   = 0;
            decoder->branch_map = 0;
        }

        if (decoder->bpred.miss_predict_carry_out)
        {
            /* carry in any miss-predict from the previous packet */
            decoder->bpred.miss_predict_carry_out = false;
            decoder->bpred.miss_predict_carry_in = true;
        }
        else if (is_branch(get_instr(decoder, decoder->last_sent_addr, &instr)))
        {
            /* 1 unprocessed branch if this instruction is a branch */
            const uint32_t branch = te_inst->branch ? 1 : 0;
            decoder->branch_map |= (branch << decoder->branches);
            decoder->branches++;
        }

        if ( (TE_INST_SUBFORMAT_START == te_inst->subformat) &&
             (!decoder->start_of_trace) )
        {
            follow_execution_path(decoder, decoder->last_sent_addr, te_inst);
            /* Note: follow_execution_path() can call unrecoverable_error() */
            if (TE_ERROR_OKAY != decoder->error_code)
            {
                return; /* return immediately if an unrecoverable error */
            }
        }
        else
        {
            /*
             * Firstly, update "last_pc" to be the current PC.
             * This is essentially so that the diagnostics emitted from disseminate_pc() looks right!
             * After we return from disseminate_pc(), we will update it again!
             */
            decoder->last_pc = decoder->pc;
            decoder->pc = decoder->last_sent_addr;
            disseminate_pc(decoder);
            /*
             * To avoid the (unlikely, but not impossible) possibility that the
             * instructions currently at "last_pc" and "pc" happen to satisfy
             * the constraints in is_sequential_jump(), we need to guarantee
             * that does not happen, when we next call follow_execution_path().
             * Thus we update "last_pc" to a "spurious" value ... that is a
             * value which will always cause is_sequential_jump() to be false.
             * We choose "pc" as such a spurious value to write to "last_pc".
             * Thus the predicate is_sequential_jump(pc,pc) will never be true.
             * Ensure is_sequential_jump() deterministically returns
             * false immediately after the first format 3 packet,
             * even though the previous PC is not known.
             */
            decoder->last_pc = decoder->pc;
        }
        decoder->start_of_trace = false;
        /*
         * The specification contains the following words:
         *      Throughout this document, the term "synchronization packet"
         *      is used. This refers specifically to format 3, subformat 0
         *      and subformat 1 packets.
         * Perform all the necessary re-initialization actions here,
         * on receipt of such a "synchronization packet".
         *
         * At this point, we should be processing either a format 3
         * subformat 0 or a subformat 1 packet, as we would have
         * already returned if it was a support or context packet.
         *
         * The trace-encoder will reinitialise the jump target cache on sync,
         * and will only ever send an index after having already sent the
         * address, hence the decoder’s jump target cache entries are always
         * guaranteed to be valid when referenced. Thus there is no need to
         * reinitialise/invalidate the decoder’s jump target cache at all!
         */
        decoder->irstack_depth = 0;
    }
    else
    {
        decoder->non_sync_packets++;

        /* carry in any miss-predict from the previous packet */
        decoder->bpred.miss_predict_carry_in = decoder->bpred.miss_predict_carry_out;
        decoder->bpred.miss_predict_carry_out = false;

        if (decoder->start_of_trace)
        {
            /* This should not be possible! */
            unrecoverable_error(decoder, TE_ERROR_NOT_FORMAT3, NULL);
            return; /* return immediately if an unrecoverable error */
        }

        /* extract the latest address, and update last_sent_addr */
        if (te_inst->with_address)
        {
            if (decoder->options.full_address)
            {
                decoder->last_sent_addr  = (te_inst->address << decoder->discovery_response.iaddress_lsb);
            }
            else
            {
                decoder->last_sent_addr += (te_inst->address << decoder->discovery_response.iaddress_lsb);
            }
        }

        /* assume we do not have a branch_count */
        decoder->bpred.correct_predictions = 0;

        if ( (decoder->options.branch_prediction) &&
             (TE_INST_FORMAT_0_EXTN == te_inst->format) &&
             (TE_INST_EXTN_BRANCH_PREDICTOR == te_inst->extension) )
        {
            assert(te_inst->u.bpred.correct_predictions);
            assert(decoder->branches <= 1u);
            decoder->statistics.num_extention[te_inst->extension]++;
            decoder->bpred.use_bmap_first =
                (!!decoder->branches) &&
                (!decoder->bpred.miss_predict_carry_in);
            decoder->bpred.correct_predictions = te_inst->u.bpred.correct_predictions;
            decoder->branches += te_inst->u.bpred.correct_predictions;
            /* if no address, then one additional miss-predict too */
            if (!te_inst->with_address)
            {
                decoder->branches++;
                decoder->stop_at_last_branch = true;
                decoder->bpred.miss_predict_carry_out = true;
            }
        }
        else if ( (decoder->options.jump_target_cache) &&
                  (TE_INST_FORMAT_0_EXTN == te_inst->format) &&
                  (TE_INST_EXTN_JUMP_TARGET_CACHE == te_inst->extension) )
        {
            decoder->statistics.num_extention[te_inst->extension]++;
            decoder->stop_at_last_branch = false;
            /* use the address in the jump target cache */
            assert(te_inst->u.jtc.index < elements_of(decoder->jump_target));
            decoder->last_sent_addr = decoder->jump_target[te_inst->u.jtc.index];
            if ( (decoder->debug_stream) &&
                 (decoder->debug_flags & TE_DEBUG_JUMP_TARGET_CACHE) )
            {
                fprintf(decoder->debug_stream,
                    "jump-cache: using jump_target[%x] = %" PRIx64 "\n",
                    te_inst->u.jtc.index,
                    decoder->last_sent_addr);
            }
            /* is there also a branch-map included ? */
            if (te_inst->branches)
            {
                decoder->branch_map |= te_inst->branch_map << (decoder->bpred.miss_predict_carry_in ? 0 : decoder->branches);
                decoder->branches += te_inst->branches;
            }
        }
        else
        {
            if ( (TE_INST_FORMAT_2_ADDR == te_inst->format) ||
                 (te_inst->with_address) )
            {
                decoder->stop_at_last_branch = false;
                if (decoder->options.jump_target_cache)
                {
                    /* find the (direct-mapped) index into the jump target cache */
                    const size_t jtc_index =
                        te_get_jtc_index(decoder->last_sent_addr, &decoder->discovery_response);
                    /* add the current address to the jump target cache */
                    decoder->jump_target[jtc_index] = decoder->last_sent_addr;
                    if ( (decoder->debug_stream) &&
                         (decoder->debug_flags & TE_DEBUG_JUMP_TARGET_CACHE) )
                    {
                        fprintf(decoder->debug_stream,
                            "jump-cache: writing %" PRIx64 " to jump_target[%x]\n",
                            decoder->last_sent_addr,
                            te_inst->u.jtc.index);
                    }
                }
            }
            if (TE_INST_FORMAT_1_DIFF == te_inst->format)
            {
                decoder->stop_at_last_branch = !te_inst->with_address;
                /*
                 * Branch map will contain <= 1 branch
                 * (1 if last reported instruction was a branch)
                 */
                if (decoder->bpred.miss_predict_carry_in)
                {
                    decoder->branch_map = te_inst->branch_map;
                }
                else
                {
                    decoder->branch_map |= te_inst->branch_map << decoder->branches;
                }
                if (0 == te_inst->branches)
                {
                    decoder->branches += TE_MAX_NUM_BRANCHES;
                }
                else
                {
                    decoder->branches += te_inst->branches;
                }
            }
        }
        follow_execution_path(decoder, decoder->last_sent_addr, te_inst);
        /* Note: follow_execution_path() can call unrecoverable_error() */
        if (TE_ERROR_OKAY != decoder->error_code)
        {
            return; /* return immediately if an unrecoverable error */
        }
    }
}


/*
 * Initialize a new instance of a trace-decoder (the state for one instance).
 * If "decoder" is NULL on entry, then memory will be dynamically
 * allocated, otherwise it must point to a pre-allocated region large enough.
 * This returns a pointer to the internal "state" of the trace-decoder.
 *
 * If this function allocated memory (decoder==NULL on entry), the memory
 * should be released (by calling free()), when the instance of the
 * trace-decoder is no longer required.
 */
te_decoder_state_t * te_open_trace_decoder(
    te_decoder_state_t * decoder,
    te_get_instruction_t * const get_instruction,
    te_do_custom_instruction_t * const do_custom_instruction,
    te_advance_decoded_pc_t * const advance_decoded_pc,
    void * const user_data,
    const rv_isa isa)
{
    if (decoder)
    {
        /* use provided memory, but zero it for ONE trace-decoder instance */
        memset(decoder, 0, sizeof(te_decoder_state_t));
    }
    else
    {
        /* allocate (and zero) memory for ONE trace-decoder instance */
        decoder = calloc(1, sizeof(te_decoder_state_t));
        assert(decoder);
    }

    /* copy all the call-back function pointers provided */
    assert(get_instruction);
    decoder->get_instruction = get_instruction;
    decoder->do_custom_instruction = do_custom_instruction;
    decoder->advance_decoded_pc = advance_decoded_pc;

    /* bind the "user-data" to the allocated memory */
    decoder->user_data = user_data;
    decoder->isa = isa;

    /*
     * initialize some of the fields, as per the pseudo-code.
     * no need to re-initialize anything that should be zero/false!
     */
    decoder->pc = TE_SENTINEL_BAD_ADDRESS;
    decoder->last_pc = TE_SENTINEL_BAD_ADDRESS;
    decoder->last_sent_addr = TE_SENTINEL_BAD_ADDRESS;
    decoder->start_of_trace = true;

    /* initialize the branch predictor lookup table */
    te_initialize_bpred_table(&decoder->bpred);

    /*
     * finally, copy some default fields into the decoder's state,
     * faking-up initial te_inst support and discovery_response packets.
     */
    decoder->discovery_response = default_discovery_response;
    decoder->options = default_support_options;
    decoder->encoder_mode = TE_ENCODER_MODE_DELTA;

    return decoder;
}


/*
 * if we have any yet, print out the decoded cache statistics
 */
void te_print_decoded_cache_statistics(
    const te_decoder_state_t * const decoder)
{
    assert(decoder);

    const float same = (float)(decoder->num_same)*100.0f/(float)decoder->num_gets;
    const float hits = (float)(decoder->num_hits)*100.0f/(float)decoder->num_gets;

    if ((decoder->debug_stream) && (decoder->num_gets))  /* ensure we do not divide by zero */
    {
        fprintf(decoder->debug_stream,
            "decoded-cache: same = %7lu (%5.2f%%),  hits = %8lu (%5.2f%%),"
            "total = %8lu,  combined hit-rate = %.2f%%\n",
            decoder->num_same, same,
            decoder->num_hits, hits,
            decoder->num_gets,
            same + hits);
    }
}
