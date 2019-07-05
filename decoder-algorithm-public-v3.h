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


#ifndef TE_DECODER_ALGORITHM_PUBLIC_H
#define TE_DECODER_ALGORITHM_PUBLIC_H


/*
 * Use the modified riscv-disassembler open-source library to decode
 * RISC-V instructions. This repository is available from:
 *
 * https://github.com/ultrasoc/riscv-disassembler/tree/ultrasoc
 *
 * The library header ("riscv-disas.h") defines the following types:
 *      rv_decode, rv_inst, and rv_isa.
 */
#include "riscv-disas.h"


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


/*
 * for non-GNUC compilers, ignore the GNU __attribute__ extensions.
 */
#ifndef __GNUC__
#   define __attribute__(...)     /* gobble up all parameters */
#endif  /* __GNUC__ */


/*
 * Define the maximum size of the "return-stack" (must be a power of 2),
 * which is only used when "implicit_return" is true.
 * If not defined elsewhere, define TE_MAX_CALL_DEPTH here.
 */
#if !defined(TE_MAX_CALL_DEPTH)
#   define TE_MAX_CALL_DEPTH (1u<<9)   /* 2^9 = 512 slots */
#endif  /* TE_MAX_CALL_DEPTH */


/*
 * There is a relatively high cost of calling the function get_instr(),
 * and this function is called at lot! This function may need to:
 *  1) retrieve an instruction from an Elf binary (for a given address)
 *  2) decode the retrieved instruction (using riscv-disassembler)
 *  3) generate a human-friendly disassembly line to be printed
 * This function is potentially called multiple times each time the PC
 * is advanced. For S/W efficiency reasons, it is worth the effort to
 * minimize the cost of all these calls. This is especially the case
 * when the trace-decoder is reconstructing the execution of a loop, as
 * the get_instr() function will be called with the exact same values
 * many times in short succession. The chosen solution is a pure software
 * cache, which does not map on to the trace encoder hardware at all.
 *
 * We create a simple (direct-mapped) cache of recent instruction decodes,
 * using the array decoded_cache[] in the te_decoder_state_s structure.
 * This will hold 100% of the slots with 16-bit instructions, but only
 * 50% of the slots with 32-bit instructions, etcetera. As the "index"
 * is the bottom n-bits of the address (after shifting it right by one).
 *
 * We now define a few macros to dimension and map this decode cache.
 * Note: a cache size of 2^10 resulted in a hit-rate of 99.12% for coremark!
 */
#if !defined(TE_DECODED_CACHE_BITS)
#   define TE_DECODED_CACHE_BITS    (10)        /* 2^10 = 1024 slots */
#endif  /* TE_DECODED_CACHE_BITS */
#define TE_DECODED_CACHE_SIZE       (1u<<TE_DECODED_CACHE_BITS)
#define TE_SLOT_NUMBER(address)     (((address)>>1)&(TE_DECODED_CACHE_SIZE-1u))


/* variables that need to hold a target's address should use te_address_t */
typedef uint64_t te_address_t;


/*
 * The following structure is used to hold the decoded and
 * disassembled information for a single RISC-V instruction.
 */
typedef struct
{
    rv_decode   decode;     /* from the riscv-disassembler repo */
    unsigned    length;     /* instruction size (in bytes) */
    char        line[80];   /* disassembly line for printing */
} te_decoded_instruction_t;


/*
 * The following structure is used to hold all the state
 * for a single instance of a trace-decoder ... this allows
 * a plurality of trace-decoders to be running simultaneously,
 * with each core being traced having its own unique instance
 * of this structure (and hence state)
 */
typedef struct te_decoder_state_s
{
    /* Reconstructed program counter */
    te_address_t pc;
    /* PC of previously retired instruction */
    te_address_t last_pc;
    /* Number of branches to process */
    unsigned int branches;
    /* Bit vector of not taken/taken (1/0) status for branches */
    uint32_t branch_map;    /* a maximum of 32 such taken bits */
    /* Flag to indicate reconstruction is to end at the final branch */
    bool stop_at_last_branch;
    /* Flag to indicate that reported address from format != 3 was
     * not following an uninferrable jump (and is therefore inferred) */
    bool inferred_address;
    /* true if 1st trace message still to be processed */
    bool start_of_trace;
    /* top of stack, zero == call stack is empty */
    size_t call_counter;
    /* memory for the "call-stack" (only when "implicit_return" is 1) */
    te_address_t return_stack[TE_MAX_CALL_DEPTH];
    /*
     * Reconstructed address from te_inst messages.
     * Only used in process_te_inst(), logically "static" therein
     * Note: pseudo-code has this at global scope (for persistence)
     */
    te_address_t address;

    /* pointer to user-data, whatever was passed to te_open_trace_decoder() */
    void * user_data;

    /* the ISA to use (for riscv-disassembler) */
    rv_isa isa;

    /* maintain a counter that increments each time the PC is changed */
    unsigned long instruction_count;  /* for statistics only */

    /* see comment above for an explanation of this decode cache */
    te_decoded_instruction_t decoded_cache[TE_DECODED_CACHE_SIZE];

    /* maintain a few statistics about decoded_cache[] */
    unsigned long num_gets;
    unsigned long num_same;
    unsigned long num_hits;
} te_decoder_state_t;


/*
 * cut-down list of fields from a te_inst message.
 * This is the subset of fields actually used by the
 * pseudo-code, with the same names and semantics.
 */
typedef struct
{
    te_address_t address;
    unsigned format;        /* 2-bits */
    unsigned subformat;     /* 2-bits */
    unsigned branches;      /* 5-bits */
    unsigned branch_map;    /* up to 31-bits */
    bool branch;            /* 1-bit */
    bool updiscon;          /* 1-bit */
} te_inst_t;


typedef enum
{
    QUAL_STATUS_NO_CHANGE = 0,
    QUAL_STATUS_ENDED_REP = 1,
    QUAL_STATUS_RESERVED  = 2,
    QUAL_STATUS_ENDED_NTR = 3
} te_qual_status_t;


/*
 * cut-down list of fields from a te_support message.
 * This is the subset of fields actually used by the
 * pseudo-code, with the same names and semantics.
 */
typedef struct
{
    bool                implicit_return;/* 1-bit */
    bool                full_address;   /* 1-bit */
    unsigned int        support_type;   /* 4-bits */
    te_qual_status_t    qual_status;    /* 2-bits */
} te_support_t;


/*
 * The following are external functions DEFINED by this code.
 * See the associated C source file for their semantics.
 */
extern void te_process_te_inst(
    te_decoder_state_t * const decoder,
    const te_inst_t * const te_inst);

extern void te_process_te_support(
    te_decoder_state_t * const decoder,
    const te_support_t * const te_support);

extern te_decoder_state_t * te_open_trace_decoder(
    te_decoder_state_t * decoder,
    void * const user_data,
    const rv_isa isa);

extern void te_print_decoded_cache_statistics(
    const te_decoder_state_t * const decoder);


/*
 * The following are external functions USED by this code to:
 *
 *  1) print some trace-decoding diagnostics
 *
 *  2) retrieve the raw binary instruction value,
 *     and its length, at a given address
 *
 *  3) notify the user that the PC has been updated
 *
 * Users of this code are expected to implement each of
 * these functions as appropriate, as they will be called
 * by the trace-decoder algorithm from time to time.
 *
 * Some of these functions are passed a "user_data" void pointer,
 * which is whatever was passed to te_open_trace_decoder().
 */
extern void te_log_printf(
    const char * const format, ...)
    __attribute__ ((format (printf, 1, 2)));

extern unsigned te_get_instruction(
    void * const user_data,
    const te_address_t address,
    rv_inst * const instruction);

extern void te_advance_decoded_pc(
    void * const user_data,
    const te_address_t old_pc,
    const te_address_t new_pc,
    const te_decoded_instruction_t * const new_instruction);


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif  /* TE_DECODER_ALGORITHM_PUBLIC_H */
