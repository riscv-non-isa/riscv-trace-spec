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


#ifndef TE_CODEC_UTILITIES_H
#define TE_CODEC_UTILITIES_H


#include "decoder-algorithm-public.h"


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


extern size_t te_get_jtc_index(
    const te_address_t address,
    const te_discovery_response_t * const discovery_response);

extern size_t te_get_bpred_index(
    const te_address_t address,
    const te_discovery_response_t * const discovery_response);

extern te_bpred_state_t te_next_bpred_state(
    const te_bpred_state_t old_state,
    const bool branch_taken);

extern void te_initialize_bpred_table(
    te_bpred_t * const bpred);


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif  /* TE_CODEC_UTILITIES_H */
