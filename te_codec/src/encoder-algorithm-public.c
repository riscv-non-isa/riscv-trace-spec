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


/*
 * define the maximum number of branches in a te_inst packet
 */
#define TE_MAX_NUM_BRANCHES     31

/*
 * Extract the most-significant bit of an integer.
 */
#define MSB(x)  (((x)>>(8*(sizeof(x))-1)) & 0x1)

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
};


/*
 * default run-time configuration "options" bits
 */
static const te_options_t default_support_options =
{
    .full_address = 0,      /* use differential addresses */
    .implicit_return = 0,   /* disable using return_stack[] */
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
    assert(TE_SENTINEL_BAD_ADDRESS != te_inst->address);

    const te_address_t address = te_inst->address;

    /*
     * Keep a note of the most recently sent address.
     * Both the encoder and decoder need to keep this in step.
     *
     * As a special case, this is *not* updated when a packet is only
     * sent due to the branch-map being full.
     */
    if ( (TE_INST_FORMAT_2_ADDR==te_inst->format) ||
         (TE_INST_FORMAT_3_SYNC==te_inst->format) ||
         (te_inst->branches) )
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
     * update the PC to which the peer decoder should have advanced
     */
    encoder->decoders_pc = address;

    /*
     * TO DO: implement an appropriate function to emit the te_inst packet
     * to the receiving trace-decoder, or append it to some buffer.
     *
     * NOTE: this is to be implemented by users of this code!
     */
}


static void send_te_inst_sync(
    te_encoder_state_t * const encoder,
    const te_inst_subformat_t subformat,
    const te_qual_status_t qual_status)
{
    te_inst_t te_inst = {0};

    assert(encoder);
    const te_instruction_record_t * const irecord = encoder->second;
    assert(irecord);
    /* a maximum of one branch in the branch-map is permissible here */
    assert(encoder->branches <= 1);

    /* QQQ: following may be deleted ... it is just paranoia! */
    if (encoder->branches)
    {
        assert(1 == encoder->branches);
        assert(irecord->is_branch);
        assert(encoder->branch_map == irecord->cond_code_fail);
    }
    else
    {
        assert(!irecord->is_branch);
        assert(!encoder->branch_map);
    }

    /*
     * fill in the fields for a single te_inst packet
     * ... specifically for a format 3 SYNC te_packet.
     */
    te_inst.format = TE_INST_FORMAT_3_SYNC;
    te_inst.subformat = subformat;
    te_inst.context = irecord->context;
    te_inst.privilege = irecord->priv;
        /*
         * Set to 0 if the address points to a branch
         * instruction, and the branch was taken.
         * Set to 1 if not a branch, or branch not taken.
         */
    te_inst.branch = !irecord->is_branch || irecord->cond_code_fail;
    te_inst.address = irecord->pc;
    te_inst.ecause = irecord->exception_cause;
    te_inst.interrupt = irecord->is_interrupt;
    te_inst.tval = irecord->tval;

    /*
     * fill in the qualification status for instruction trace
     * te_inst synchronization support packets.
     * also copy the current set of run-time "options" bits.
     */
    if (TE_INST_SUBFORMAT_SUPPORT == subformat)
    {
        te_inst.support.options = encoder->options;
        te_inst.support.qual_status = qual_status;
    }

    /*
     * most te_inst synchronization packet includes the context,
     * so the "pending" flag can typically be de-asserted at this juncture.
     */
    if (TE_INST_SUBFORMAT_SUPPORT != subformat)
    {
        encoder->context_pending = false;
    }

    /* finally, send the completed te_inst packet downstream */
    send_te_inst(encoder, &te_inst);

    /*
     * for "start" and "exception" synchronization te_inst packets,
     * we also reinitialize the resynchronization counter to zero.
     */
    if ( (TE_INST_SUBFORMAT_EXCEPTION == subformat) ||
         (TE_INST_SUBFORMAT_START == subformat) )
    {
        encoder->resync_count = 0;
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
static void send_te_inst_sync_support(
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
    te_inst_t te_inst = {0};

    assert(encoder);

    /*
     * for convenience, just have 2 simple names for
     * the current and next instructions.
     */
    const te_instruction_record_t * const curr = encoder->second;
    const te_instruction_record_t * const next = encoder->first;
    assert(curr);
    assert(next);

    /*
     * fill in the fields for a single te_inst packet
     * ... specifically for a NON-format 3 (SYNC) te_packet.
     *
     * Note: "is_updiscon" is true if the current instruction is
     * the result of an uninferable PC discontinuity.
     * Whereas "updiscon" is the value of the updiscon field in a
     * te_inst packet, and depends on the msb of the address field.
     *
     * That is:
     *      updiscon = is_updiscon ^ MSB(address)
     *
     * But this is only if we know that the NEXT instruction WILL
     * generate a te_inst synchronization packet (i.e. if the
     * next instruction is one of:
     *
     *      1)  an exception
     *      2)  a change in privilege levels
     *      3)  resync_count == max_resync
     *
     * Otherwise, for maximum compressibility:
     *      updiscon = MSB(address)
     */

    te_inst.branches = encoder->branches;
    te_inst.branch_map = encoder->branch_map;
    te_inst.address = curr->pc;
    if (with_address)
    {
        te_address_t address;
        const uint32_t max_resync = get_max_resync(encoder);
        bool next_generates_sync = false;
        assert(encoder->resync_count <= max_resync);

        if ( (next->is_exception)                   ||
             (curr->priv != next->priv)             ||
             (encoder->resync_count == max_resync) )
        {
            /* next instruction will generate a te_inst sync packet */
            next_generates_sync = true;
        }

        if (te_inst.branches)
        {
            /* send a differential address, with a branch-map */
            te_inst.format = TE_INST_FORMAT_1_DIFF;
            address = te_inst.address - encoder->last_sent_addr;
        }
        else
        {
            te_inst.format = TE_INST_FORMAT_2_ADDR;
            if (encoder->options.full_address)
            {
                /* send a full address, without a branch-map */
                address = te_inst.address;
            }
            else
            {
                /* send a differential address, without a branch-map */
                address = te_inst.address - encoder->last_sent_addr;
            }
        }

        /* initially assume updiscon is the msb of the address */
        te_inst.updiscon = MSB(address);

        /*
         * compute the "updiscon" field in the current te_inst packet, by
         * XOR-ing in the current is_updiscon flag, but only if the next
         * instruction will generate a synchronization te_inst packet.
         */
        if (next_generates_sync)
        {
            te_inst.updiscon ^= curr->is_updiscon;
        }
    }
    else
    {
        /* do not send an address ... but the branch-map is full */
        te_inst.format = TE_INST_FORMAT_1_DIFF;
        assert(TE_MAX_NUM_BRANCHES == te_inst.branches);
        te_inst.branches = 0;   /* special-case: full is mapped to 0 */
        /* set to false the "updiscon" field in the te_inst ... no address */
        te_inst.updiscon = false;
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
    te_instruction_record_t * const prev = encoder->third;
    te_instruction_record_t * const curr = encoder->second;
    te_instruction_record_t * const next = encoder->first;
    assert(curr);
    assert(next);

    /*
     * current instruction is a branch instruction?
     */
    if (curr->is_branch)
    {
        /*
         * Update the branch map, with the current branch.
         * Note: bit 0 represents the oldest branch instruction executed.
         */
        encoder->branch_map |= (curr->cond_code_fail ? 1u : 0u) << encoder->branches++;
        assert(encoder->branches <= TE_MAX_NUM_BRANCHES);
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
            if (encoder->call_counter < call_counter_max)
            {
                encoder->call_counter++;    /* push new function */
            }
            /* else, counter is saturated ... do not overflow */
        }

        if (curr->is_return) /* was it a function return ? */
        {
            if (encoder->call_counter)
            {
                encoder->call_counter--;    /* pop function */
            }
            /* else, counter is saturated ... do not underflow */
        }
    }

    /*
     * last instruction was an unpredictable discontinuity?
     *
     * However, do not send a te_inst packet if it was an implicit
     * function return (i.e. one popped from a call-stack counter).
     */
    if ( (prev->is_updiscon)                            &&
         (!prev->is_return || !encoder->call_counter) )
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
     * resync_count == max_resync and branch is map not empty
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
                (next->is_updiscon) ? TE_QUAL_STATUS_ENDED_UPD : TE_QUAL_STATUS_ENDED_REP;
            send_te_inst_sync_support(encoder, qual_status);
        }

        /* end of cycle ... all done */
        return;
    }

    /*
     * is the branch map full?
     */
    if (TE_MAX_NUM_BRANCHES == encoder->branches)
    {
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
        clock_the_encoder(encoder);
    }
}
