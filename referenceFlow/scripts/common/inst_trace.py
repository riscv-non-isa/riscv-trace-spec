###########################################################################################
#
# SPDX-License-Identifier: BSD-2-Clause
# SPDX-FileCopyrightText: Copyright 2019-2021 Siemens. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

from enum import IntEnum

class itype_t(IntEnum):
    """
    Instruction type input into the encoder (Table 4.4)
    The valid values are determined by the parameter itype_width_p which can be 3 or 4
    """
    ITYPE_NONE = 0
    EXCEPTION = 1
    INTERRUPT = 2
    EXCEPTION_OR_INTERRUPT_RETURN = 3
    NONTAKEN_BRANCH = 4
    TAKEN_BRANCH = 5
    UNINFERABLE_JUMP = 6
    RESERVED = 7
    UNINFERABLE_CALL = 8
    INFERABLE_CALL = 9
    UNINFERABLE_TAIL_CALL = 10
    INFERABLE_TAIL_CALL = 11
    CO_ROUTINE_SWAP = 12
    RETURN = 13
    OTHER_UNINFERABLE_JUMP = 14
    OTHER_INFERABLE_JUMP = 15


class ctype_t(IntEnum):
    """ Context type (Table 4.6) """
    UNREPORTED_CONTEXT = 0
    IMPRECISE_CONTEXT = 1
    PRECISE_CONTEXT = 2
    ASYNC_DISCON = 3


class format_t(IntEnum):
    """ Format type present in every te_inst packet (See chapter 7) """
    SYNC = 3
    ADDR = 2
    BRANCH = 1
    EXT = 0


class sync_t(IntEnum):
    """ For sync te_inst packets this is the type of sync (See chapter 7) """
    START = 0
    TRAP = 1
    CONTEXT = 2
    SUPPORT = 3

class qual_status_t(IntEnum):
    """ Indicates qualification status (See table 7.4) """
    NO_CHANGE = 0
    ENDED_REP = 1
    TRACE_LOST = 2
    ENDED_NTR = 3
