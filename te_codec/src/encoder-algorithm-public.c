/*
 * Copyright (c) 2019 UltraSoC Technologies Limited
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


/*
 *  NOTES
 *  -----
 *
 *  The trace-encoder does *not* need to know which ISA is being used
 *  (e.g. RV32 -v- RV64)!  That is, this encoder does not need to
 *  decode any opcodes (e.g. C.JAL which is RV32 only), instead its
 *  input stimulus includes fields such as IS_CALL to indicate a
 *  jump instruction.
 */


#include <assert.h>
#include <stdlib.h>
#include "encoder-algorithm-public.h"
#include "decoder-algorithm-internal.h"
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
    .call_counter_width = 7,    /* maximum of 512 calls on return_stack[] */
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
    .jump_target_cache = false, /* disable using jump_target[] */
    .branch_prediction = false, /* disable using a branch predictor */
};


static const te_set_trace_t default_set_trace =
{
    .max_resync = 1u,           /* resync timer expires at 16 times this value */
    .resync_cycles = false,     /* resync timer counts te_inst packets when false */
};


/*
 * Process an unrecoverable error with the trace-encoder's algorithm.
 * This is indicative of a serious malfunction - this should never happen!
 * This function prints a diagnostic, and it will call exit() to terminate.
 * NOTE: this function will never return to its caller!
 * However, any functions registered with atexit() will be called.
 */
static void unrecoverable_error(
    const char * const message)
{
    assert(message);

    fprintf(stderr, "ERROR: %s\n", message);
    fflush(stderr);

    exit(1);    /* do not return ... bye bye */
}


static uint32_t get_max_resync(
    te_encoder_state_t * const encoder)
{
    uint32_t max_resync;

    assert(encoder);

    if (encoder->set_trace.max_resync)  /* != zero */
    {
        /* timer must reach 16 * max_resync */
        max_resync = encoder->set_trace.max_resync << 4;
    }
    else                                /* == zero */
    {
        /* A value of zero means the timer must reach 2^16. */
        max_resync = 1u << 16;
    }

    return max_resync;
}


static void clock_the_pipeline(
    te_encoder_state_t * const encoder,
    const te_instruction_record_t * const irecord)
{
    assert(encoder);
    assert(irecord);

    /*
     * The H/W trace-encoder uses a 3-stage pipeline.
     * The first stage is used to provide information about the next instruction,
     * and the 3rd stage provides information about the previous instruction.
     * Newly retired instructions are stored in the 1st stage, with each older
     * instruction progressing to the next higher stage, e.g. each cycle does:
     *      contents of third-stage is discarded
     *      contents of second-stage copied to third-stage
     *      contents of first-stage copied to second-stage
     *      newly retired instruction copied to first-stage
     */
    switch (encoder->pipeline_depth)
    {
        case 1:         /* only stage 1 currently valid */
            encoder->second = encoder->first;
            /*lint -fallthrough */ /* no break */
        case 0:         /* pipe-line is empty */
            encoder->pipeline_depth++;
            break;

        case 2:         /* only stages 1 and 2 currently valid */
            encoder->pipeline_depth++;
            /*lint -fallthrough */ /* no break */
        case 3:         /* pipe-line is full */
            encoder->third = encoder->second;
            encoder->second = encoder->first;
            break;

        default:        /* this should never happen */
            unrecoverable_error("illegal value for trace-encoder pipeline_depth");
    }

    /*
     * The following are always done every time the pipeline is clocked.
     * ... irrespective of the active current depth of the pipeline.
     * The newly retired instruction is always added to the first-stage.
     */
    encoder->first = &encoder->stage[encoder->next_slot];
    *encoder->first = *irecord;
    encoder->next_slot++;
    encoder->next_slot %= elements_of(encoder->stage);
}


static void send_te_inst(
    te_encoder_state_t * const encoder,
    te_inst_t * const te_inst)
{
    assert(encoder);
    assert(te_inst);
    assert( (TE_SENTINEL_BAD_ADDRESS != te_inst->address) ||
            ( (TE_INST_FORMAT_3_SYNC == te_inst->format) &&
              (TE_INST_SUBFORMAT_SUPPORT == te_inst->subformat) ) );

    const te_address_t address = te_inst->address;

    /*
     * adjust the "address", if it will be sent as a
     * differential-address, and not as a full-address.
     */
    if ( (encoder->options.full_address)            ||
         (TE_INST_FORMAT_3_SYNC==te_inst->format) )
    {
        /* use full-address ... no need to adjust it */
    }
    else
    {
        /* use differential-address ... calculate the delta */
        te_inst->address = address - encoder->last_sent_addr;
    }

    /*
     * The bottom few bits of an instruction address will be
     * zero, and are compressible, by right-shifting them out.
     *
     * However, for the compression to work, the most significant
     * instruction address bit must be retained, i.e. we need
     * to ensure that we use sign-extended shift operations.
     *
     * Trick! First cast the unsigned address to be signed,
     * and then right-shift the signed representation, finally
     * cast it back to an unsigned address.
     * Note: we "cast", not convert ... the binary representation
     * should not change during the two assignments.
     */
    int64_t signed_address;             /* signed */
    signed_address = te_inst->address;  /* unsigned to signed */
                /* signed right-shift, replicating the sign-bit */
    signed_address >>= encoder->discovery_response.iaddress_lsb;
    te_inst->address = signed_address;  /* signed to unsigned */

    /*
     * Keep a note of the most recently sent address.
     * Both the encoder and decoder need to keep this in step.
     */
    if (te_inst->with_address)
    {
        encoder->last_sent_addr = address;
    }

    /*
     * Advance the re-sync counter ...
     * ... but only if we are not counting system clock cycles!
     * Note: this counter should be updated asynchronously otherwise!
     */
    if (!encoder->set_trace.resync_cycles)
    {
        encoder->resync_count++;    /* counting te_inst packets */
    }

    /*
     * re-initialize the branch-map
     */
    encoder->branches = 0;
    encoder->branch_map = 0;

    /*
     * update the PC to which the peer trace-decoder state-machine
     * should advance, on receipt of the current te_inst packet.
     */
    encoder->decoders_pc = address;

    /*
     * Finally, send the filled-in "te_inst" packet data structure
     * downstream, typically to be consumed by a RISC-V trace-decoder.
     *
     * Note: The called function is to be implemented by users,
     * as the encapsulation of the fields to be transmitted is
     * outwith the scope of this reference code, which codifies
     * the heart of the trace-encoder algorithm.
     */
    te_send_te_inst(encoder->user_data, te_inst);

    /*
     * re-initialize the counter of the number of correctly
     * predicted branches for the branch predictor
     */
    encoder->bpred.correct_predictions = 0;
}


static void send_te_inst_sync(
    te_encoder_state_t * const encoder,
    const te_inst_subformat_t subformat,
    const te_qual_status_t qual_status)
{
    te_inst_t te_inst = {0};

    assert(encoder);

    /*
     * Note: take care ... irecord might be NULL here!
     * e.g. after enabling the trace-encoder, before any instructions records have
     * been added to the instruction pipeline, a support packet should be sent.
     */
    const te_instruction_record_t * const irecord = encoder->second;

    /* a maximum of one branch in the branch-map is permissible here */
    assert(encoder->branches <= 1);

    /*
     * fill in the common fields for a single te_inst packet
     * ... specifically for a format 3 SYNC te_packet.
     */
    te_inst.format = TE_INST_FORMAT_3_SYNC;
    te_inst.subformat = subformat;

    /*
     * Some of the sub-formats omit the "address" field, hence it is
     * strictly optional, and it should really be assigned in the following
     * switch statement, but only for the sub-formats that actually use it.
     * However, it is generally helpful for debugging purposes ...
     * thus we will unconditionally copy an address here.
     *
     * Warning: there may not be an irecord (for a support packet).
     */
    te_inst.address = irecord ?
        irecord->pc :               /* a valid PC */
        TE_SENTINEL_BAD_ADDRESS;    /* no valid PC */

    /*
     * now fill in the subformat-specific fields
     */
    switch(subformat)
    {
        case TE_INST_SUBFORMAT_EXCEPTION:
            assert(irecord);
            te_inst.ecause = irecord->exception_cause;
            te_inst.interrupt = irecord->is_interrupt;
            te_inst.tval = irecord->tval;
            /*lint -fallthrough */ /* no break */
        case TE_INST_SUBFORMAT_START:
            assert(irecord);
            te_inst.with_address = true;
            /*
             * Set to 0 if the address points to a branch
             * instruction, and the branch was taken.
             * Set to 1 if not a branch, or branch not taken.
             */
            te_inst.branch = !irecord->is_branch || irecord->cond_code_fail;
            /*lint -fallthrough */ /* no break */
        case TE_INST_SUBFORMAT_CONTEXT:
            assert(irecord);
            te_inst.context = irecord->context;
            te_inst.privilege = irecord->priv;
            break;

        case TE_INST_SUBFORMAT_SUPPORT:
            /*
             * fill in the qualification status for instruction trace
             * te_inst synchronization support packets.
             * also copy the current set of run-time "options" bits.
             */
            te_inst.support.options = encoder->options;
            te_inst.support.qual_status = qual_status;
            break;

        default:
            assert(0);  /* should never get here! */
    }

    /* invalidate the entire jump target cache, if enabled */
    if (encoder->options.jump_target_cache)
    {
        memset(encoder->jump_target, 0, sizeof(encoder->jump_target));
    }

    /* send the completed te_inst packet downstream */
    send_te_inst(encoder, &te_inst);

    /*
     * most te_inst synchronization packets includes the context,
     * so the "pending" flag can typically be de-asserted
     * after sending most te_inst synchronization packets.
     */
    if (TE_INST_SUBFORMAT_SUPPORT != subformat)
    {
        encoder->context_pending = false;
    }

    /*
     * The specification contains the following words:
     *      Throughout this document, the term "synchronization packet"
     *      is used. This refers specifically to format 3, subformat 0
     *      and subformat 1 packets.
     * Perform all the necessary re-initialization actions here,
     * on generation of such a "synchronization packet".
     */
    if ( (TE_INST_SUBFORMAT_EXCEPTION == subformat) ||
         (TE_INST_SUBFORMAT_START == subformat) )
    {
        /* reinitialize the resynchronization counter to zero. */
        encoder->resync_count = 0;

        /*
         * The specification requires that the counter for a call-stack is
         * reset to zero when we send a "synchronization packet".
         * Optionally, we may want to log (for debugging) exactly how
         * many current entries in the call-stack we are about to drop!
         * Note: Dropping such return addresses from the call-stack is
         * NOT a real problem ... just an efficiency impact!
         */
        if (encoder->call_counter)
        {
            if ((encoder->debug_stream) && (encoder->debug_flags & TE_DEBUG_CALL_STACK))
            {
                fprintf(encoder->debug_stream,
                    "call-stack: dropping a total of %" PRIu64
                    " entries from the call-stack!\n",
                    encoder->call_counter);
            }
            encoder->call_counter = 0;  /* drop them all */
        }
    }
}


/*
 * Send a te_inst synchronization support packet.
 *
 * This should be sent after any of the following:
 *
 *  1) the trace-encoder initially being enabled
 *
 *  2) the configuration of the trace-encoder changes
 *
 *  3) the tracing ends (e.g. unqualified, halted)
 */
void te_send_te_inst_sync_support(
    te_encoder_state_t * const encoder,
    const te_qual_status_t qual_status)
{
    assert(encoder);

    /* send the support te_inst packet */
    send_te_inst_sync(encoder,
        TE_INST_SUBFORMAT_SUPPORT,
        qual_status);
}


static void send_te_inst_non_sync(
    te_encoder_state_t * const encoder,
    const bool with_address)
{
    bool jump_cache_hit = false;    /* PC is in jump_target[] ? */
    assert(encoder);

    /*
     * for convenience, just have simple names for
     * the previous, current and next instructions.
     */
    const te_instruction_record_t * const prev = encoder->third;
    const te_instruction_record_t * const curr = encoder->second;
    const te_instruction_record_t * const next = encoder->first;
    assert(prev);
    assert(curr);
    assert(next);

    /*
     * fill in the fields for a single te_inst packet
     * ... specifically for a NON-format 3 (SYNC) te_packet.
     */
    te_inst_t te_inst =
    {
        .with_address = with_address,
        .address = curr->pc,
        .branches = encoder->branches,
        .branch_map = encoder->branch_map,
    };

    /*
     * do we need to update the jump target cache ?
     */
    if ( (with_address) &&
         (encoder->options.jump_target_cache) )
    {
        /* find the (direct-mapped) index into the jump target cache */
        const size_t jtc_index =
            te_get_jtc_index(curr->pc, &encoder->discovery_response);
        /* have we just performed an uninferrable updiscon ? */
        if (prev->is_updiscon)
        {
            /* is it in the jump target cache ? */
            if (encoder->jump_target[jtc_index] == curr->pc)
            {
                jump_cache_hit = true;   /* yes it is! */
                encoder->statistics.jtc.hits++;
            }
            encoder->statistics.jtc.lookups++;
        }
        if ( (encoder->debug_stream) &&
             (encoder->statistics.jtc.lookups) &&
             (encoder->debug_flags & TE_DEBUG_JUMP_TARGET_CACHE) )
        {
            fprintf(encoder->debug_stream,
                "jump-cache: %" PRIx64 " -> %" PRIx64 ", jump_target[%" PRIx64 "] = %5s,"
                " hit-rate = %" PRIu64 "/%" PRIu64 " (%.2f%%)\n",
                prev->pc,
                curr->pc,
                jtc_index,
                (!prev->is_updiscon) ? "write" : jump_cache_hit ? "HIT" : "miss",
                encoder->statistics.jtc.hits,
                encoder->statistics.jtc.lookups,
                (double)(encoder->statistics.jtc.hits)/((double)encoder->statistics.jtc.lookups)*100.0);
        }
        /*
         * unconditionally update the jump target cache with
         * the current target ... do this for ALL non-sync packets,
         * if the jump target cache is enabled.
         */
        encoder->jump_target[jtc_index] = curr->pc;
        te_inst.jtc_index = jtc_index;
        /*
         * finally, is a jump target cache extension packet #0 legal,
         * and is it really the best (most efficient) option ?
         * If not, then treat it as if we did not get a hit.
         */
        if (jump_cache_hit) /* got a hit ? */
        {
            if (encoder->branches > TE_MAX_NUM_BRANCHES)
            {
                /* hit, but no legal format #0 packet is possible */
                jump_cache_hit = false;
            }
            else
            {
                /* hit, but ask helper function which is best */
                jump_cache_hit = te_prefer_jtc_extension(encoder->user_data, &te_inst);
            }
        }
    }

    /*
     * now work out exactly what format packet to use ...
     */
    if (encoder->branches > TE_MAX_NUM_BRANCHES)
    {
        /*
         * send a branch predictor efficiency extension packet
         * i.e. a branch-count, optionally with an address
         */
        te_inst.format = TE_INST_FORMAT_0_EXTN;
        te_inst.extension = TE_INST_EXTN_BRANCH_PREDICTOR;
        encoder->statistics.num_extention[te_inst.extension]++;
        te_inst.correct_predictions = encoder->bpred.correct_predictions;
        te_inst.branches = 0;
        te_inst.branch_map = 0;
        assert(encoder->branches - ((with_address) ? 0u : 1u) == encoder->bpred.correct_predictions);

        /* update min, max, and accumulators for the branch-predictor */
        if (encoder->bpred.correct_predictions > encoder->statistics.bpred.longest_sent)
        {
            encoder->statistics.bpred.longest_sent = encoder->bpred.correct_predictions;
        }
        if ( (!encoder->statistics.bpred.shortest_sent) ||
             (encoder->bpred.correct_predictions < encoder->statistics.bpred.shortest_sent) )
        {
            encoder->statistics.bpred.shortest_sent = encoder->bpred.correct_predictions;
        }
        encoder->statistics.bpred.sum_sent += encoder->bpred.correct_predictions;
        if (with_address)
        {
            encoder->statistics.bpred.with_address++;
        }
        else
        {
            encoder->statistics.bpred.without_address++;
        }
    }
    else if (jump_cache_hit)
    {
        /*
         * send a jump target cache efficiency extension packet
         * i.e. a jump target index, optionally with a branch-map
         */
        te_inst.format = TE_INST_FORMAT_0_EXTN;
        te_inst.extension = TE_INST_EXTN_JUMP_TARGET_CACHE;
        encoder->statistics.num_extention[te_inst.extension]++;
        if (te_inst.branches)
        {
            encoder->statistics.jtc.with_bmap++;
        }
        else
        {
            encoder->statistics.jtc.without_bmap++;
        }
    }
    else if (!with_address)
    {
        /* send a branch-map, without an address */
        te_inst.format = TE_INST_FORMAT_1_DIFF;
        if (TE_MAX_NUM_BRANCHES == te_inst.branches) /* is the branch-map full? */
        {
            te_inst.branches = 0;   /* special-case: full is mapped to 0 */
        }
    }
    else if (te_inst.branches)
    {
        /* send an address, with a branch-map */
        te_inst.format = TE_INST_FORMAT_1_DIFF;
    }
    else
    {
        /* send an address, without a branch-map */
        te_inst.format = TE_INST_FORMAT_2_ADDR;
    }

    /*
     * Update the "updiscon" field in the current te_inst packet, to
     * determine if the transmitted bit value of the updison field is
     * the same (or inverted) value as the previously transmitted bit.
     *
     * Note: "is_updiscon" is true if the given instruction is
     * the result of an uninferable PC discontinuity.
     * Whereas "updiscon" is the field in a te_inst_t structure,
     * which will be used to calculate the bit physically transmitted.
     *
     * The value of the bit physically transmitted depends on two things:
     *
     *      1) the value of the previously transmitted bit
     *         (typically the msb of the address field)
     *      2) the "updiscon" field in the te_inst_t structure
     *
     * That is:
     *      transmitted-value = MSB(address) ^ te_inst.updiscon
     *
     * But te_inst.updiscon will only be true if we know that the
     * NEXT instruction WILL generate a te_inst synchronization
     * packet (i.e. if the next instruction is one of:
     *
     *      1)  an exception
     *      2)  a change in privilege levels
     *      3)  resync_count == max_resync
     *
     * ... AND the PREVIOUS instruction has is_updiscon == true.
     *
     * Otherwise, for maximum compressibility:
     *      transmitted-value = MSB(address)
     * i.e. te_inst.updiscon = false
     *
     * Where there is no address, (e.g. with_address == 0) then the
     * most-significant bit of the branch-map shall be used instead.
     */
    if ( (next->is_exception)                   ||
         (curr->priv != next->priv)             ||
         (encoder->resync_count == get_max_resync(encoder)) )
    {
        /* next instruction will generate a te_inst sync packet */
        if (prev->is_updiscon)
        {
            /*
             * The previous instruction was an updiscon, so we do want
             * to invert the previously transmitted bit when we
             * eventually transmit the updiscon field in the bit-stream.
             */
            te_inst.updiscon = true;
            encoder->statistics.num_updiscon_fields++;
        }
    }

    /* finally, send the completed te_inst packet downstream */
    send_te_inst(encoder, &te_inst);
}


static void clock_the_encoder(
    te_encoder_state_t * const encoder)
{
    assert(encoder);

    /*
     * for convenience, just have 3 simple names for
     * the previous, current and next instructions.
     * Note: previous may be unknown here (i.e. NULL).
     */
    const te_instruction_record_t * const prev = encoder->third;
    const te_instruction_record_t * const curr = encoder->second;
    const te_instruction_record_t * const next = encoder->first;
    assert(curr);
    assert(next);

    /*
     * current instruction is a branch instruction?
     */
    if (curr->is_branch)
    {
        const bool branch_taken = !curr->cond_code_fail;

        /*
         * Update the branch map, with the current branch.
         * Note: bit 0 represents the oldest branch instruction executed.
         */
        encoder->branch_map |= (branch_taken ? 0u : 1u) << encoder->branches++;
        assert( (encoder->options.branch_prediction) ||
                (encoder->branches <= TE_MAX_NUM_BRANCHES) );

        if (encoder->options.branch_prediction)
        {
            /* find the (direct-mapped) index into the branch predictor table */
            const size_t bpred_index =
                te_get_bpred_index(curr->pc, &encoder->discovery_response);
            /* retrieve the extant state from the branch predictor table */
            const te_bpred_state_t old_state =
                (te_bpred_state_t)(encoder->bpred.table[bpred_index]);
            const bool predicted_outcome = !!(old_state & 0x2u);
            const bool previous_outcome  = !!(old_state & 0x1u);

            /* calculate the next value of the branch predictor state */
            const te_bpred_state_t new_state = te_next_bpred_state(old_state, branch_taken);

            /* act appropriately if we predicted correctly or not */
            if (predicted_outcome == branch_taken)
            {
                encoder->bpred.correct_predictions++;
                encoder->statistics.bpred.correct++;
            }
            else
            {
                encoder->statistics.bpred.incorrect++;
            }

            /* optionally, print out what we have done */
            if ( (encoder->debug_stream) &&
                 (encoder->debug_flags & TE_DEBUG_BRANCH_PREDICTION) )
            {
                fprintf(encoder->debug_stream,
                    "bpred-%u: %" PRIx64 ", bpred_table[%02" PRIx64 "] = %u%u -> %u%u,  "
                    "%9s  %" PRIx64 "/%" PRIx64 "  run=%" PRIu64 "  %s\n",
                    ++encoder->bpred.serial,
                    curr->pc,
                    bpred_index,
                    predicted_outcome,      /* MSB */
                    previous_outcome,       /* LSB */
                    !!(new_state & 0x2u),   /* MSB */
                    !!(new_state & 0x1u),   /* LSB */
                    branch_taken ? "TAKEN" : "not taken",
                    encoder->statistics.bpred.correct,
                    encoder->statistics.bpred.correct + encoder->statistics.bpred.incorrect,
                    encoder->bpred.correct_predictions,
                    (predicted_outcome == branch_taken) ? "CORRECTLY PREDICATED" : "miss-predicted");
            }

            /* finally update the lookup table with the new state */
            encoder->bpred.table[bpred_index] = (uint8_t)new_state;
        }
    }

    /*
     * last instruction was an exception?
     * ... if there was a last instruction!
     */
    if (prev && prev->is_exception)
    {
        /* send an exception synchronization te_inst packet */
        send_te_inst_sync(encoder,
            TE_INST_SUBFORMAT_EXCEPTION,
            0);     /* qual_status is not relevant here */

        /* end of cycle ... all done */
        return;
    }

    /*
     * Test for any of the following for the current instruction:
     *      1)  the 1st qualified instruction
     *      2)  a change in privilege levels
     *      3)  resumed from a HALT (i.e. first un-halted)
     *      4)  resync_count > max_resync
     * Warning: prev may be NULL here ... be careful! However,
     * it should only ever be NULL if encoder->start_sent == false.
     */
    assert(prev || !encoder->start_sent);
    if ( (!encoder->start_sent)                         ||
         (prev->priv != curr->priv)                     ||
         ( (prev->is_halted) && (!curr->is_halted) )    ||
         (encoder->resync_count > get_max_resync(encoder)) )
    {
        /* send a start synchronization te_inst packet */
        send_te_inst_sync(encoder,
            TE_INST_SUBFORMAT_START,
            0);     /* qual_status is not relevant here */

        /* record that a start synchronization packet has been sent */
        encoder->start_sent = true;

        /* end of cycle ... all done */
        return;
    }

    /* if we get here, then we expect all 3 stages to be filled */
    assert(prev && encoder->start_sent);

    /*
     * has the context changed?
     *
     * if so, for now, just set a "pending" flag to ensure we shall
     * (on a best effort basis) forward this change to the decoder.
     */
    assert(!encoder->context_pending);
    if (prev->context != curr->context)
    {
        encoder->context_pending = true;
    }

    /*
     * if the "implicit-return" feature is enabled, then we also
     * need to maintain a call-counter, otherwise the call-counter
     * is assumed to always be zero.
     *
     * With a call-counter, returns will be marked as updiscon only
     * if the call-counter is zero when they occur.
     * However, calls may or may not be marked as updiscons.
     */
    if (encoder->options.implicit_return)       /* using a call-stack counter ? */
    {
        if (curr->is_call)   /* was it a (non-tail) function call ? */
        {
            const size_t call_counter_max = (size_t)1 << (encoder->discovery_response.call_counter_width + 2);
            assert(encoder->call_counter <= call_counter_max);
            assert(call_counter_max <= TE_MAX_CALL_DEPTH);
            /*
             * We will *always* push the newest return address on to the call-stack.
             * The question is: do we drop the oldest return address on the call-stack?
             * Optionally show what we will push onto the call stack
             */
            if ((encoder->debug_stream) && (encoder->debug_flags & TE_DEBUG_CALL_STACK))
            {
                /*
                 * TODO: calculate and print the return address that will
                 * be pushed onto the call-stack.
                 */
                fprintf(encoder->debug_stream,
                    "call-stack: pushed [%3" PRIu64 "]\n",
                    encoder->call_counter);
            }
            if (encoder->call_counter < call_counter_max)
            {
                /*
                 * counter is not yet saturated ... call-stack has room
                 * for at least one more return addresses to be added
                 * so, just push the new return address on the call-stack
                 */
                encoder->call_counter++;
            }
            else
            {
                /*
                 * counter is already saturated ... do not overflow!
                 * We will drop the oldest return address on the call-stack.
                 * Optionally advise the user we have dropped one return address!
                 * Note: Dropping such a return address from the call-stack is
                 * NOT a real problem ... just an efficiency impact!
                 */
                if ((encoder->debug_stream) && (encoder->debug_flags & TE_DEBUG_CALL_STACK))
                {
                    fprintf(encoder->debug_stream,
                        "call-stack: call-counter at maximum (%" PRIu64
                        ") ... dropping oldest return address!\n",
                        encoder->call_counter);
                }
            }
        }

        if (curr->is_return) /* was it a function return ? */
        {
            if (encoder->call_counter)
            {
                encoder->call_counter--;    /* pop function */
                /* optionally show what we will pop from the call stack */
                if ((encoder->debug_stream) && (encoder->debug_flags & TE_DEBUG_CALL_STACK))
                {
                    fprintf(encoder->debug_stream,
                        "call-stack: popped [%3" PRIu64 "] --> %08" PRIx64 "\n",
                        encoder->call_counter,
                        next->pc);
                }
                /*
                 * if we are able to pop a return address successfully from the
                 * call stack, then we must not treat the return as an updiscon.
                 * Effectively, such a return is treated as an inferrable jump!
                 * Over-write "is_updiscon" so next time this function is
                 * called, prev->is_updiscon will be false!
                 * Note: cast is just to remove the "const" qualifier.
                 */
                ((te_instruction_record_t*)curr)->is_updiscon = false;
            }
            else
            {
                /*
                 * counter is already at minimum ... do not underflow!
                 * This means we cannot "pop" the return address, and we will
                 * have to revert to non implicit-return mode ... that is,
                 * we will need to treat this return as a normal updiscon!
                 * Optionally advise the user we failed to pop a return address.
                 * Note: Dropping such a return address from the call-stack is
                 * NOT a real problem ... just an efficiency impact!
                 */
                if ((encoder->debug_stream) && (encoder->debug_flags & TE_DEBUG_CALL_STACK))
                {
                    fprintf(encoder->debug_stream,
                        "call-stack: call-counter at minimum (%" PRIu64
                        ") ... no return address to pop!\n",
                        encoder->call_counter);
                }
            }
        }
    }

    /*
     * last instruction was an unpredictable discontinuity?
     *
     * However, do not send a te_inst packet if it was an implicit
     * return (i.e. one that was popped from a call-stack).
     */
    if (prev->is_updiscon)
    {
        /*
         * send a te_inst packet with address of current
         * instruction ... that is, the first temporal
         * address after the updiscon instruction.
         */
        send_te_inst_non_sync(
            encoder,
            true);      /* te_inst packet WITH address */

        /* end of cycle ... all done */
        return;
    }

    /*
     * resync_count == max_resync and branch map is not empty
     */
    if ( (encoder->branches) &&
         (encoder->resync_count == get_max_resync(encoder)) )
    {
        /*
         * A corollary of the trace encoder algorithm, is that we
         * should only ever get here if branches is exactly one!
         * That is, we will send a packet with an address, and
         * with exactly one branch in the branch-map.
         */
        assert(1 == encoder->branches);
        /* send a te_inst packet with address of current instruction */
        send_te_inst_non_sync(
            encoder,
            true);      /* te_inst packet WITH address */

        /* end of cycle ... all done */
        return;
    }

    /*
     * Test for any of the following for the next instruction:
     *      1)  transitions to an unqualified instruction (i.e. current is final qualified).
     *      2)  a change in privilege levels and the branch map is not empty
     *      3)  transitions to halted (i.e. current is final un-halted instruction)
     *      4)  an exception (unless the current one is also an exception)
     *          (Note: A te_inst packet is not sent if the 1st instruction
     *          of the trap handler itself takes an exception!)
     */
    if ( ( (curr->is_qualified) && (!next->is_qualified) )      ||
         ( (curr->priv != next->priv) && (encoder->branches) )  ||
         ( (!curr->is_halted) && (next->is_halted) )            ||
         ( (!curr->is_exception) && (next->is_exception) ) )
    {
        /*
         * send a te_inst packet with address of current
         * instruction ... that is, the address of the
         * "final traced instruction".
         */
        send_te_inst_non_sync(
            encoder,
            true);      /* te_inst packet WITH address */

        /*
         * in some cases, also send a te_inst sync support packet after
         * the "final traced instruction" te_inst packet is sent.
         */
        if ( (!next->is_qualified)  ||
             (next->is_halted) )
        {
            const te_qual_status_t qual_status =
                (next->is_updiscon) ?
                    TE_QUAL_STATUS_ENDED_UPD :
                    TE_QUAL_STATUS_ENDED_REP;
            te_send_te_inst_sync_support(encoder, qual_status);
        }

        /* end of cycle ... all done */
        return;
    }

    /*
     * is the branch map full?
     * and if the branch-predictor is enabled, then there
     * is also at least one branch that was miss-predicted
     * ... if so, then send a full branch-map now.
     */
    if ( (TE_MAX_NUM_BRANCHES == encoder->branches) &&
         (TE_MAX_NUM_BRANCHES != encoder->bpred.correct_predictions) )
    {
        /* send a te_inst packet without an address */
        send_te_inst_non_sync(encoder,
            false);     /* te_inst packet WITHOUT an address */

        /* end of cycle ... all done */
        return;
    }

    /*
     * if the branch predictor is enabled, and the current instruction
     * is a branch that was miss-predicted, and we have at least 32
     * branches (of which this branch is the only miss-prediction),
     * then send a te_inst packet with a branch-count now.
     */
    if ( (encoder->branches > TE_MAX_NUM_BRANCHES) &&
         (encoder->branches != encoder->bpred.correct_predictions) )
    {
        assert(curr->is_branch);
        assert(encoder->branches == encoder->bpred.correct_predictions + 1u);

        /* send a te_inst packet without an address */
        send_te_inst_non_sync(encoder,
            false);     /* te_inst packet WITHOUT an address */

        /* end of cycle ... all done */
        return;
    }

    /*
     * is there a pending notification about a changed context?
     * if so, and we have not sent any te_inst packets in this
     * cycle, then send one now.
     * The fact we are here, ipso facto confirms that no te_inst
     * packets have been sent in this cycle.
     */
    if (encoder->context_pending)
    {
        /* send an context synchronization te_inst packet */
        send_te_inst_sync(encoder,
            TE_INST_SUBFORMAT_CONTEXT,
            0);     /* qual_status is not relevant here */
    }

    /* end of cycle ... all done */
}


/*
 * Initialize a new instance of a trace-encoder (the state for one instance).
 * If "encoder" is NULL on entry, then memory will be dynamically
 * allocated, otherwise it must point to a pre-allocated region large enough.
 * This returns a pointer to the internal "state" of the trace-encoder.
 *
 * If this function allocated memory (encoder==NULL on entry), the memory
 * should be released (by calling free()), when the instance of the
 * trace-encoder is no longer required.
 */
te_encoder_state_t * te_open_trace_encoder(
    te_encoder_state_t * encoder,
    void * const user_data)
{
    if (encoder)
    {
        /* use provided memory, but zero it for ONE trace-encoder instance */
        memset(encoder, 0, sizeof(te_encoder_state_t));
    }
    else
    {
        /* allocate (and zero) memory for ONE trace-encoder instance */
        encoder = calloc(1, sizeof(te_encoder_state_t));
        assert(encoder);
    }

    /* bind the "user-data" to the allocated memory */
    encoder->user_data = user_data;

    /*
     * initialize some of the fields of the state-machine
     * no need to re-initialize anything that should be zero/false!
     */
    encoder->last_sent_addr = TE_SENTINEL_BAD_ADDRESS;
    encoder->decoders_pc = TE_SENTINEL_BAD_ADDRESS;

    /* initialize the branch predictor lookup table */
    te_initialize_bpred_table(&encoder->bpred);

    /*
     * finally, copy some default fields into the encoder's state,
     * faking-up initial support, discovery_response and
     * set_trace packets.
     */
    encoder->discovery_response = default_discovery_response;
    encoder->options = default_support_options;
    encoder->set_trace = default_set_trace;

    return encoder;
}


/*
 * Process a single trace-encoder cycle.
 * Called each time an instruction retires.
 */
void te_encode_one_irecord(
    te_encoder_state_t * const encoder,
    const te_instruction_record_t * const irecord)
{
    assert(encoder);
    assert(irecord);
    assert(TE_SENTINEL_BAD_ADDRESS != irecord->pc);

    /* clock the new retired instruction into our pipeline */
    clock_the_pipeline(encoder, irecord);

    /*
     * as long as there are at least 2 stages occupied, and the second
     * one is qualified, then we can update the trace-encoder state-machine.
     *
     * Recall, the trace-encoder operates coherently with the second stage.
     *
     * Note: it is safe to update the trace-encoder state-machine, even
     * if the 3rd stage is empty. This is because the 1st instruction
     * will send a start sync te_inst packet, and exit the cycle
     * before any attempt is made to access the 3rd stage.
     */
    assert(encoder->second || !encoder->third);
    if (encoder->second &&              /* 2nd stage is filled */
        encoder->second->is_qualified)  /* ... and qualified ? */
    {
        /* advance the count of PC transitions */
        encoder->statistics.num_instructions++;

        clock_the_encoder(encoder);
    }
}
