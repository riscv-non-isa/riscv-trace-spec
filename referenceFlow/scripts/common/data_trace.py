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

class dtype_t(IntEnum):
    """
    Data type input into the encoder (Table 4.12)
    """
    LOAD = 0,
    STORE = 1,
    CSR_READ_WRITE = 4,
    CSR_READ_SET = 5,
    CSR_READ_CLEAR = 6,
    ATOMIC_SWAP = 8,
    ATOMIC_ADD = 9,
    ATOMIC_AND = 10,
    ATOMIC_OR = 11,
    ATOMIC_XOR = 12,
    ATOMIC_MAX = 13,
    ATOMIC_MIN = 14,
    STORE_FAILURE = 15,
    DTYPE_INVALID = 16,


class iformat_t(IntEnum):
    """ Format type present in every te_inst packet (See chapter 7) """
    SYNC = 3
    ADDR = 2
    BRANCH = 1
    EXT = 0

class dformat_t(IntEnum):
    """ Format type present in every data packet (See chapter 8) """
    LOAD_ALIGNED = 0
    LOAD_UNALIGNED = 1
    STORE_ALIGNED = 2
    STORE_UNALIGNED = 3
    CSR = 5
    ATOMIC = 6

class diff_t(IntEnum):
    FULL_ADDR_DATA = 0
    DIFF_ADDR_XOR_DATA = 1
    DIFF_ADDR_FULL_DATA = 2
    DIFF_ADDR_DIFF_DATA = 3

class diff_addr_t(IntEnum):
    FULL = 0
    DIFF = 1

class diff_data_t(IntEnum):
    FULL = 0
    COMPRESSED = 1
    DIFF = 3

class compress_t(IntEnum):
    NONE = 0
    XOR = 1
    DIFF = 2
    BEST = 3

class atomic_t(IntEnum):
    """ Atomic subtype values """
    SWAP = 0
    ADD = 1
    AND = 2
    OR = 3
    XOR = 5
    MAX = 6
    MIN = 7

class csr_t(IntEnum):
    """ CSR subtype values """
    RW = 0
    RS = 1
    RC = 2
