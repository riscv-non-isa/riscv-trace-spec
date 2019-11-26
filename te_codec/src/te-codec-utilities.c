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


#include <assert.h>
#include "te-codec-utilities.h"


/*
 * find the (direct-mapped) index into the jump target cache,
 * for address "address".
 */
size_t te_get_jtc_index(
    const te_address_t address,
    const te_discovery_response_t * const discovery_response)
{
    assert(discovery_response);

    const size_t mask =
        ((size_t)1u << discovery_response->jump_target_cache_size) - 1u;

    assert(mask < TE_JUMP_TARGET_CACHE_SIZE);

    const size_t jtc_index =
        (address >> discovery_response->iaddress_lsb) & mask;

    return jtc_index;
}


/*
 * find the (direct-mapped) index into the branch predictor
 * lookup table, for address "address".
 */
size_t te_get_bpred_index(
    const te_address_t address,
    const te_discovery_response_t * const discovery_response)
{
    assert(discovery_response);

    const size_t mask =
        ((size_t)1u << discovery_response->branch_prediction_size) - 1u;

    assert(mask < TE_BRANCH_PREDICTOR_SIZE);

    const size_t bpred_index =
        (address >> discovery_response->iaddress_lsb) & mask;

    return bpred_index;
}


/*
 * Update the old branch-predictor state, and return a new
 * state given: the old state, and knowledge if the current
 * branch is taken or not.
 *
 * 00: predict not taken, transition to 01 if prediction fails;
 * 01: predict not taken, transition to 00 if prediction succeeds, else 11;
 * 10: predict taken, transition to 11 if prediction succeeds, else 00;
 * 11: predict taken, transition to 10 if prediction fails.
 *
 * The MSB represents the predicted outcome.
 * The LSB represents the most recent actual outcome.
 */
te_bpred_state_t te_next_bpred_state(
    const te_bpred_state_t old_state,
    const bool branch_taken)
{
    /* assume there will be no change to the state */
    te_bpred_state_t new_state = old_state;

    switch (old_state)
    {
        case TE_BPRED_00:
            if (branch_taken)
            {
                new_state = TE_BPRED_01;
            }
            break;

        case TE_BPRED_01:
            if (!branch_taken)
            {
                new_state = TE_BPRED_00;
            }
            else
            {
                new_state = TE_BPRED_11;
            }
            break;

        case TE_BPRED_10:
            if (branch_taken)
            {
                new_state = TE_BPRED_11;
            }
            else
            {
                new_state = TE_BPRED_00;
            }
            break;

        case TE_BPRED_11:
            if (!branch_taken)
            {
                new_state = TE_BPRED_10;
            }
            break;

        default:
            assert(0);
    }

    return new_state;
}


/*
 * re-initialize all the elements in the branch-predictor
 * look-up table, to the default state.
 */
void te_initialize_bpred_table(
    te_bpred_t * const bpred)
{
    assert(bpred);

    memset(bpred->table,
        TE_BPRED_01,
        sizeof(bpred->table));
}
