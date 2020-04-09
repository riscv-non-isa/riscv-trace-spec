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
 * on MinGW, a different format attribute is needed for printf checking.
 */
#if defined(__USE_MINGW_ANSI_STDIO)
#   define TE_PRINTF_FORMAT __MINGW_PRINTF_FORMAT   /* for MinGW */
#else
#   define TE_PRINTF_FORMAT printf      /* for non-MinGW systems */
#endif  /* __USE_MINGW_ANSI_STDIO */


/*
 * Define some debug flags to control which types of debug we wish to enable.
 * These should be OR-ed together, and stored in the "debug_flags" field.
 * Note: if debug_stream == NULL then all enabled flags are ignored.
 */
#define TE_DEBUG_PC_TRANSITIONS     (1u)
#define TE_DEBUG_IMPLICIT_RETURN    (1u << 1)
#define TE_DEBUG_FOLLOW_PATH        (1u << 2)
#define TE_DEBUG_PACKETS            (1u << 3)
#define TE_DEBUG_JUMP_TARGET_CACHE  (1u << 4)
#define TE_DEBUG_BRANCH_PREDICTION  (1u << 5)


/*
 * Define the maximum size of the implicit-return (IR) stack,
 * which must be a power of 2.
 * This "irstack" is only used when the implicit return mode
 * is enabled, i.e. "implicit_return" is true.
 *
 * Note, this IR "stack" is implementation dependent, and it
 * may be implemented on the trace-encoder H/W as any of
 * the following three distinct alternatives:
 *
 *  1) A saturating "call-counter" (and not a real stack), which
 *     will never over-flow nor under-flow.
 *     Such a scheme is low cost, and will work as long as
 *     traced programs are "well behaved".
 *     In this case call_counter_size shall be non-zero, and
 *     return_stack_size shall be zero.
 *
 *  2) A real stack, with each function return address being
 *     stored in it as each new function call is made.
 *     This is fully robust for all programs, but is more
 *     expensive to implement.
 *     In this case return_stack_size shall be non-zero, and
 *     call_counter_size shall be zero.
 *
 *  3) Not implemented at all.
 *     In this case both return_stack_size and
 *     call_counter_size shall be zero.
 *
 * If not defined elsewhere, define TE_MAX_IRSTACK_DEPTH here.
 */
#if !defined(TE_MAX_IRSTACK_DEPTH)
#   define TE_MAX_IRSTACK_DEPTH (1u<<9)   /* 2^9 = 512 slots */
#endif  /* TE_MAX_IRSTACK_DEPTH */


/*
 * Define "cache_size_p", the number of bits used to dimension
 * the size of the "jump target cache".
 * This cache is only used when the run-time option "jump_target_cache" is true.
 * If not defined elsewhere, define TE_CACHE_SIZE_P here.
 */
#if !defined(TE_CACHE_SIZE_P)
#   define TE_CACHE_SIZE_P  (7u)    /* 2^7 = 128 entries */
#endif  /* TE_CACHE_SIZE_P */
#define TE_JUMP_TARGET_CACHE_SIZE (1u<<TE_CACHE_SIZE_P)


/*
 * Define "bpred_size_p", the number of bits used to dimension
 * the size of the "branch predictor lookup table".
 * This table is only used when the run-time option "branch_prediction" is true.
 * If not defined elsewhere, define TE_BPRED_SIZE_P here.
 */
#if !defined(TE_BPRED_SIZE_P)
#   define TE_BPRED_SIZE_P  (7u)    /* 2^7 = 128 entries */
#endif  /* TE_BPRED_SIZE_P */
#define TE_BRANCH_PREDICTOR_SIZE (1u<<TE_BPRED_SIZE_P)


/*
 * Define the maximum number of branches in a branch-map.
 * This is the maximum length of a branch-map (in bits).
 */
#define TE_MAX_NUM_BRANCHES     31u


/*
 * There is a relatively high cost of calling the function
 * te_get_and_disassemble_instr(), which is aliased to get_instr(),
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
 * using the array decoded_cache[] in the te_decoder_state_t structure.
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


/*
 * Define a value to initialize the PC, which is a known "bad address".
 * Detect if we ever try and use this address!
 */
#define TE_SENTINEL_BAD_ADDRESS     0xbadaddu


/* variables that need to hold a target's address should use te_address_t */
typedef uint64_t te_address_t;


/* enumerate the 2-bit te_inst format types */
typedef enum
{
    TE_INST_FORMAT_0_EXTN = 0,      /* 00 (optional efficiency extensions) */
    TE_INST_FORMAT_1_DIFF = 1,      /* 01 (diff-delta) */
    TE_INST_FORMAT_2_ADDR = 2,      /* 10 (addr-only) */
    TE_INST_FORMAT_3_SYNC = 3       /* 11 (sync) */
} te_inst_format_t;

/* enumerate the 2-bit te_inst subformat types */
typedef enum
{
    TE_INST_SUBFORMAT_START = 0,    /* 00 (start) */
    TE_INST_SUBFORMAT_EXCEPTION = 1,/* 01 (exception) */
    TE_INST_SUBFORMAT_CONTEXT = 2,  /* 10 (context) */
    TE_INST_SUBFORMAT_SUPPORT = 3   /* 11 (support) */
} te_inst_subformat_t;

/* enumerate the optional efficiency extensions */
typedef enum
{
    TE_INST_EXTN_BRANCH_PREDICTOR = 0,  /* branch predictor */
    TE_INST_EXTN_JUMP_TARGET_CACHE = 1, /* jump target cache */
} te_inst_extensions_t;
#define TE_NUM_EXTENSIONS       2       /* number of extensions */


/* enumerate the 2-bit qualification status */
typedef enum
{
    TE_QUAL_STATUS_NO_CHANGE = 0,   /* 00 (no_change) */
    TE_QUAL_STATUS_ENDED_REP = 1,   /* 01 (ended_reported) */
    TE_QUAL_STATUS_TRACE_LOST = 2,  /* 10 (trace_lost) */
    TE_QUAL_STATUS_ENDED_UPD = 3    /* 11 (ended_updiscon) */
} te_qual_status_t;

/* enumerate the 2-bit branch prediction state */
typedef enum
{
    TE_BPRED_00 = 0,    /* 00: predict not taken, transition to 01 if prediction fails. */
    TE_BPRED_01 = 1,    /* 01: predict not taken, transition to 00 if prediction succeeds, else 11. */
    TE_BPRED_10 = 2,    /* 10: predict taken, transition to 11 if prediction succeeds, else 00. */
    TE_BPRED_11 = 3     /* 11: predict taken, transition to 10 if prediction fails. */
} te_bpred_state_t;

/* enumerate the 2-bit branch_fmt field, for format 0 packets with a branch_count field */
typedef enum
{
    TE_BRANCH_FMT_00_NO_ADDR = 0,       /* 00: packet has no address field */
    TE_BRANCH_FMT_10_ADDR = 2,          /* 10: packet has an address field */
    TE_BRANCH_FMT_11_ADDR_FAIL = 3      /* 11: packet contains an address of a branch which was a miss-prediction */
} te_branch_fmt_t;

/*
 * enumerate the known set of trace algorithms, used to indicate
 * which "operating mode" the trace-encoder is currently using.
 *
 * The initial focus is with the "compressed branch trace", hence
 * there is initially only a single algorithm ("delta mode 1")
 * listed here ... more may be added in the future.
 *
 * Note: TE_ENCODER_MODE_BITS should be the minimum number of bits
 * required to encode the largest value of type te_encoder_mode_t.
 */
typedef enum
{
    TE_ENCODER_MODE_DELTA = 0,          /* 00 (delta): delta mode 1 (aka compressed branch trace) */
} te_encoder_mode_t;
#define TE_ENCODER_MODE_BITS    (1u)    /* number of bits to send te_encoder_mode_t */

/*
 * enumerate the sub-set of "exception causes" (ecause) used
 */
typedef enum
{
    TE_ECAUSE_ILLEGAL_INSTRUCTION = 2,  /* illegal instruction exception */
    TE_ECAUSE_ECALL_U_MODE = 8,         /* environment call from U-mode */
    TE_ECAUSE_ECALL_S_MODE = 9,         /* environment call from S-mode */
    TE_ECAUSE_ECALL_M_MODE = 11,        /* environment call from M-mode */
} te_ecause_t;


/*
 * enumerate the set of error codes for the function
 * unrecoverable_error()
 */
typedef enum
{
    TE_ERROR_OKAY = 0,          /* this is NOT an error condition! */
    TE_ERROR_DEPLETED,
    TE_ERROR_UNINFERRABLE,
    TE_ERROR_BAD_FOLLOW,
    TE_ERROR_UNPROCESSED,
    TE_ERROR_IMPLICT_EXCEPTION,
    TE_ERROR_NOT_FORMAT3,
    TE_ERROR_NUM_ERRORS         /* must be last in list */
} te_error_code_t;


/*
 * The following structure is used to hold the decoded and
 * disassembled information for a single RISC-V instruction.
 *
 * Empirically, 84 bytes is the length of the longest
 * disassembled line observed thus far, but other (unseen)
 * instructions could be longer (e.g. custom instructions)!
 */
typedef struct
{
    rv_decode   decode;     /* from the riscv-disassembler repo */
    unsigned    length;     /* instruction size (in bytes) */
    char        line[88];   /* disassembly line for printing */
} te_decoded_instruction_t;


/*
 * The following is used to cache a sub-set of the fields in the
 * discovery_response packet for this Trace-Encoder IP block.
 */
typedef struct te_discovery_response_t
{
    unsigned int version;               /* 9-bits */
    unsigned int call_counter_size;     /* 4-bits */
    unsigned int return_stack_size;     /* 4-bits */
    unsigned int iaddress_lsb;          /* 2-bits */
    unsigned int jump_target_cache_size;/* 3-bits */
    unsigned int branch_prediction_size;/* 3-bits */
} te_discovery_response_t;


/*
 * The following is used to hold the values of all the
 * run-time configuration bits.  The number of bits and
 * definitions are implementation dependent.
 */
typedef struct
{
    bool        implicit_return;        /* 1-bit */
    bool        implicit_exception;     /* 1-bit */
    bool        full_address;           /* 1-bit */
    bool        jump_target_cache;      /* 1-bit */
    bool        branch_prediction;      /* 1-bit */
} te_options_t;

/*
 * The following may be used to "serialize" the above
 * run-time configuration options, when they are to be
 * sent in a format 3, sub-format 3 "support" packet.
 * However, these values are all implementation defined!
 */
#define TE_OPTIONS_IMPLICIT_RETURN      (1u)
#define TE_OPTIONS_IMPLICIT_EXCEPTION   (1u << 1)
#define TE_OPTIONS_FULL_ADDRESS         (1u << 2)
#define TE_OPTIONS_JUMP_TARGET_CACHE    (1u << 3)
#define TE_OPTIONS_BRANCH_PREDICTION    (1u << 4)
#define TE_OPTIONS_NUM_BITS             (5u)    /* number of bits to send te_options_t */


/*
 * cut-down list of fields from a te_inst
 * synchronization support packet.
 * This is the subset of fields actually used by the
 * pseudo-code, with the same names and semantics.
 */
typedef struct
{
    unsigned int        support_type;   /* 4-bits */
    te_encoder_mode_t   encoder_mode;   /* TE_ENCODER_MODE_BITS-bits */
    te_qual_status_t    qual_status;    /* 2-bits */
    te_options_t        options;        /* run-time configuration bits */
} te_support_t;


/*
 * The following is used to accumulate various counters
 * and metrics about te_inst packets received, and the
 * traced instructions ... ultimately to print various
 * statistics about a trace session.
 */
typedef struct
{
    /* counters for each type of te_inst format */
    size_t num_format[4];       /* index is two bits */
    /* counters for each type of te_inst format 0 sub-format */
    size_t num_extention[TE_NUM_EXTENSIONS];    /* variable bits */
    /* counters for each type of te_inst format 3 sub-format */
    size_t num_subformat[4];    /* index is two bits */

    /* counter for each instruction that is retired */
    size_t num_instructions;
    /* counter for each instruction that raises an exception  */
    size_t num_exceptions;

    /*
     * counters for total number of branch instructions,
     * and for the number of branches actually taken
     */
    size_t num_branches;
    size_t num_taken;

    /* counter for the number of unpredicted discontinuities */
    size_t num_updiscons;

    /*
     * counter for the number of times an inverted updiscon
     * field was transmitted in a te_inst packet.
     * i.e. the number of times that the updiscon field was
     * different from the MSB of the adjacent address field.
     */
    size_t num_updiscon_fields;

    /* counter for the number of function calls + returns */
    size_t num_calls;
    size_t num_returns;

    /* counters for the jump target cache, jump_target[] */
    struct
    {
        size_t lookups;
        size_t hits;
        size_t with_bmap;    /* total number of packets with a branch-map */
        size_t without_bmap; /* total number of packets without a branch-map */
    }   jtc;

    /* counters for the branch predictor table, bpred_table[] */
    struct
    {
        size_t correct;         /* number of correct predictions */
        size_t incorrect;       /* number of incorrect predictions */
        size_t shortest_sent;   /* shortest correct predictions sent */
        size_t longest_sent;    /* longest correct predictions sent */
        size_t sum_sent;        /* sum of correct predictions sent */
        size_t with_address;    /* total number of packets with an address */
        size_t without_address; /* total number of packets without an address */
    }   bpred;
} te_statistics_t;


/*
 * The following structure is used to hold the relevant information
 * pertaining to a single branch predictor, which is an optional feature.
 */
typedef struct
{
    /* the total number of correctly predicted branches */
    uint64_t correct_predictions;  /* maximum value is 2^32 - 1 + 31 */

    /* the following is actually of type te_bpred_state_t */
    uint8_t table[TE_BRANCH_PREDICTOR_SIZE];

    /* should the branch predictor use branch-map[0] first ? */
    bool use_bmap_first;

    /* do we "carry" a branch miss-predict from one packet to the next ? */
    bool miss_predict_carry_in;   /* carry in from previous packet */
    bool miss_predict_carry_out;  /* carry out to next packet */

    /* a serial number for each branch ... used only for debugging */
    unsigned int serial;
} te_bpred_t;


/*
 * list of fields used in a te_inst packet.
 */
typedef struct te_inst_t
{
    /* following used by all formats */
    te_inst_format_t format;/* 2-bits */
    te_address_t address;   /* width of instruction address bus */

    /*
     * the following flag is not transmitted directly in a packet, but
     * it is used to help qualify fields that are.
     */
    bool with_address;      /* true if the "address" field is valid */

    /*
     * The following field is not transmitted at all in any real
     * packets from the hardware trace-encoder. However, it may
     * be used by a software trace-encoder, purely to help with
     * debugging activities of the software trace-decoder itself.
     * That is, this field optionally might include a count of
     * the number of instructions that will be reconstructed by
     * following the execution path.
     * The core algorithm does not depend on this field at all.
     */
    size_t icount;          /* instruction count */

    /* following not used by TE_INST_FORMAT_3_SYNC */
    unsigned branches;      /* 5-bits */
    uint32_t branch_map;    /* up to 31-bits */
    bool notify;            /* 1-bit */
    bool updiscon;          /* 1-bit */
    bool irfail;            /* 1-bit */
    uint16_t irdepth;       /* up to 9-bits */
    /*
     * Warning: The "updiscon" field above has "odd" semantics!
     *
     * Originally, this code mapped the value of this field to
     * be the same as the value of the appropriate bit that was
     * physically transmitted in the bit-stream of a te_inst packet.
     *
     * However, to simply coding, the semantics have now changed and
     * it no longer is the value of the bit physically transmitted!
     * Instead it represents the value to be XOR-ed with the MSB of
     * the previous field (either address or branch_map), prior
     * to transmission.
     *
     * In other words, the responsibility to perform any and all
     * XOR operations now lie with the serializer and the de-serializer.
     * This field merely indicates if an inversion should/did occur.
     *
     * To be clear, a value of FALSE means that updiscon field should be
     * transmitted with the SAME value as the previous bit. And as a
     * corollary, a value of TRUE means that updiscon field should be
     * transmitted as the INVERTED value of the previous bit.
     * With the "previous bit" meaning the bit physically transmitted
     * immediately before the updiscon field, and that bit is the
     * most-significant-bit of either the address or the branch-map
     * fields, i.e. address[MSB], or branch-map[30].
     *
     * In most cases, this value will be false, and the updiscon
     * field will be transmitted as the same value as the previous
     * bit, which should in most cases should be compressed away.
     *
     * In addition, the fields "notify", and "irfail" also have similarly
     * odd semantics, inasmuch as a value of FALSE means these fields
     * should be transmitted with the SAME value as the previous bit.
     * And as a corollary, a value of TRUE means that these fields should
     * be transmitted as the INVERTED value of the previous bit. Again
     * the serializer and the de-serializer should perform these XORs.
     */

    /* following only used by TE_INST_FORMAT_3_SYNC */
    te_inst_subformat_t subformat;  /* 2-bits */
    uint32_t context;       /* up to 32-bits */
    uint8_t privilege;      /* up to 4-bits */
    bool branch;            /* 1-bit */
    uint16_t ecause;        /* up to 16-bits */
    bool interrupt;         /* up to 1-bit */
    te_address_t tvalepc;   /* either tval or epc (if an illegal instruction) */
    te_support_t support;   /* for a synchronization support packet */

    /* following only used by TE_INST_FORMAT_0_EXTN */
    te_inst_extensions_t extension; /* sub-format for optional efficiency extensions */
    union
    {
        struct
        {
            unsigned index; /* cache_size_p-bits, index for the jump target cache */
        }   jtc;            /* jump-target-cache specific extensions */
        struct
        {
            uint64_t correct_predictions;  /* maximum value is 2^32 - 1 + 31 */
            te_branch_fmt_t branch_fmt;
        }   bpred;          /* branch-predictor specific extensions */
    } u;                    /* union of extensions */
} te_inst_t;


/*
 * The following structure is used to hold all the state
 * for a single instance of a trace-decoder ... this allows
 * a plurality of trace-decoders to be running simultaneously,
 * with each core being traced having its own unique instance
 * of this structure (and hence state)
 */
typedef struct te_decoder_state_t
{
    /* Reconstructed program counter */
    te_address_t pc;
    /* PC of previously retired instruction */
    te_address_t last_pc;
    /* Number of branches to process */
    uint64_t branches;
    /* Bit vector of not taken/taken (1/0) status for branches */
    uint32_t branch_map;    /* a maximum of 32 such taken bits */
    /* Flag to indicate reconstruction is to end at the final branch */
    bool stop_at_last_branch;
    /* Flag to indicate that reported address from format != 3 was
     * not following an uninferrable jump (and is therefore inferred) */
    bool inferred_address;
    /* true if 1st trace packet still to be processed */
    bool start_of_trace;

    /* array holding return address stack (only when "implicit_return" is 1) */
    te_address_t return_stack[TE_MAX_IRSTACK_DEPTH];
    /* depth of the return address stack, zero == stack is empty */
    size_t irstack_depth;

    /*
     * Following is the "normalized" (i.e. un-shifted, non-differential) address
     * corresponding to the "address" field in the most recent te_inst packet.
     * Both the trace-encoder, and the trace-decoder (as peers) should
     * maintain the same value for this, and always keep them in sync.
     */
    te_address_t last_sent_addr;

    /* fields from the discovery_response packets */
    te_discovery_response_t discovery_response;

    /*
     * set of run-time configuration "option" bits from the most
     * recently received te_inst synchronization support packet
     */
    te_options_t        options;
    te_encoder_mode_t   encoder_mode;

    /* the most recent privilege level reported */
    uint8_t privilege;      /* up to 4-bits */

    /* pointer to user-data, whatever was passed to te_open_trace_decoder() */
    void * user_data;

    /* the ISA to use (for riscv-disassembler) */
    rv_isa isa;

    /* allocate memory for a "jump target cache" */
    te_address_t jump_target[TE_JUMP_TARGET_CACHE_SIZE];

    /* following used only if we enable a branch predictor */
    te_bpred_t bpred;

    /* collection of various counters, to generate statistics */
    te_statistics_t statistics;

    /* number of non-sync packets received, since last sync packet */
    uint32_t non_sync_packets;

    /* see comment above for an explanation of this decode cache */
    te_decoded_instruction_t decoded_cache[TE_DECODED_CACHE_SIZE];

    /* maintain a few statistics about decoded_cache[] */
    unsigned long num_gets;
    unsigned long num_same;
    unsigned long num_hits;

    /* the FILE I/O stream to which to write all debug info */
    FILE * debug_stream;

    /* the set of active debug flags (OR-ed together) */
    unsigned int debug_flags;

    /* error code, if an unrecoverable error was encountered */
    te_error_code_t error_code;
} te_decoder_state_t;


/*
 * The following are external functions DEFINED by this code.
 * See the associated C source file for their semantics.
 */
extern void te_process_te_inst(
    te_decoder_state_t * const decoder,
    const te_inst_t * const te_inst);

extern te_decoder_state_t * te_open_trace_decoder(
    te_decoder_state_t * decoder,
    void * const user_data,
    const rv_isa isa);

extern void te_print_decoded_cache_statistics(
    const te_decoder_state_t * const decoder);

extern te_decoded_instruction_t * te_get_and_disassemble_instr(
    te_decoder_state_t * const decoder,
    const te_address_t address,
    te_decoded_instruction_t * const instr);


/*
 * The following are external functions USED by this code to:
 *
 *  1) retrieve the raw binary instruction value,
 *     and its length, at a given address
 *
 *  2) notify the user that the PC has been updated
 *
 * Users of this code are expected to implement each of
 * these functions as appropriate, as they will be called
 * by the trace-decoder algorithm from time to time.
 *
 * Some of these functions are passed a "user_data" void pointer,
 * which is whatever was passed to te_open_trace_decoder().
 */
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
