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


#ifndef TE_ENCODER_ALGORITHM_PUBLIC_H
#define TE_ENCODER_ALGORITHM_PUBLIC_H


/*
 * include the public decoder algorithm header file
 */
#include "decoder-algorithm-public.h"


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */



/*
 * cut-down list of fields for a set_trace packet.
 * This is the subset of fields actually used by the
 * trace-encoder, with the same names and semantics.
 */
typedef struct
{
    uint16_t            max_resync;     /* 12-bits */
    bool                resync_cycles;  /* 1-bit */
} te_set_trace_t;


/*
 * The following is used to provide all the pertinent
 * information to the trace-encoder at the start of each
 * new cycle, to be processed by the trace-encoder.
 */
typedef struct
{
    te_address_t pc;            /* program counter of retired instruction */
    te_address_t tval;          /* same as instruction address width */
    uint16_t exception_cause;   /* up to 16-bits */
    uint8_t priv;               /* up to 4-bits */
    uint32_t context;           /* up to 32-bits */

    /* set of boolean flags */
    bool is_exception;
    bool is_interrupt;
    bool is_branch;
    bool is_updiscon;
    bool cond_code_fail;
    bool is_call;
    bool is_return;
    bool is_qualified;  /* is the current instruction qualified ? */
    bool is_halted;     /* true if the CPU in debug mode */
} te_instruction_record_t;


/*
 * The following structure is used to hold all the state
 * for a single instance of a trace-encoder ... this allows
 * a plurality of trace-encoders to be running simultaneously,
 * with each core being traced having its own unique instance
 * of this structure (and hence state)
 */
typedef struct
{
    /*
     * Following is the "normalized" (i.e. un-shifted, non-differential) address
     * corresponding to the "address" field in the most recent te_inst packet.
     * Both the trace-encoder, and the trace-decoder (as peers) should
     * maintain the same value for this, and always keep them in sync.
     */
    te_address_t last_sent_addr;
    /* Reconstructed program counter, on the (peer) decoder */
    te_address_t decoders_pc;
    /* Number of branches to process */
    unsigned int branches;
    /* Bit vector of not taken/taken (1/0) status for branches */
    uint32_t branch_map;    /* a maximum of 31 such taken bits */
    /* flag to indicate this not the first qualified instruction */
    bool start_sent;
    /* top of stack, zero == call stack is empty */
    size_t call_counter;
    /* flag to indicate if we need to notify due to a new context */
    bool context_pending;

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
    te_instruction_record_t stage[3]; /* hardware fixes this as 3-stages */
    te_instruction_record_t *first; /* 1st stage - pointer into one of the 'stage[3]' */
    te_instruction_record_t *second;/* 2nd stage - pointer into one of the 'stage[3]' */
    te_instruction_record_t *third; /* 3rd stage - pointer into one of the 'stage[3]' */
    size_t next_slot;       /* index into 'stage' - next one to be discarded/reused */
    unsigned int pipeline_depth;    /* number of stages currently in use */

    /* fields from the discovery_response packets */
    te_discovery_response_t discovery_response;

    /*
     * set of run-time configuration "option" bits from the most
     * recently sent te_inst synchronization support packet
     */
    te_options_t options;

    /* fields from the most recent set_trace configuration */
    te_set_trace_t set_trace;

    /* generate a te_inst synchronization packet when counter > max_resync*16 */
    uint32_t resync_count;  /* must be able to reach 2^16 */

    /* pointer to user-data, whatever was passed to te_open_trace_encoder() */
    void * user_data;

    /* allocate memory for a "jump target cache" */
    te_address_t jump_target[TE_JUMP_TARGET_CACHE_SIZE];

    /* collection of various counters, to generate statistics */
    te_statistics_t statistics;

    /* the FILE I/O stream to which to write all debug info */
    FILE * debug_stream;

    /* the set of active debug flags (OR-ed together) */
    unsigned int debug_flags;
} te_encoder_state_t;


/*
 * The following are external functions DEFINED by this code.
 * See the associated C source file for their semantics.
 */
extern void te_encode_one_irecord(
    te_encoder_state_t * const encoder,
    const te_instruction_record_t * const irecord);

extern te_encoder_state_t * te_open_trace_encoder(
    te_encoder_state_t * encoder,
    void * const user_data);

/*
 * Send a te_inst synchronization support packet.
 *
 * This should be sent after any of the following:
 *  1) the trace-encoder initially being enabled
 *  2) the configuration of the trace-encoder changes
 *  3) the tracing ends (e.g. unqualified, halted)
 */
extern void te_send_te_inst_sync_support(
    te_encoder_state_t * const encoder,
    const te_qual_status_t qual_status);


/*
 * The following is an external functions USED by this code to:
 *
 *  notify the user that the PC has been updated
 *
 * Users of this code are expected to implement each of
 * these functions as appropriate, as they will be called
 * by the trace-encoder algorithm from time to time.
 *
 * Some of these functions are passed a "user_data" void pointer,
 * which is whatever was passed to te_open_trace_encoder().
 */
extern void te_send_te_inst(
    void * const user_data,
    te_inst_t * const te_inst);


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif  /* TE_ENCODER_ALGORITHM_PUBLIC_H */
