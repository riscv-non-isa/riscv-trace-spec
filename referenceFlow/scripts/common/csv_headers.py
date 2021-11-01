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

""" Spike instruction trace CSV header """
spike_inst = [
    "VALID",
    "ADDRESS",
    "INSN",
    "PRIVILEGE",
    "EXCEPTION",
    "ECAUSE",
    "TVAL",
    "INTERRUPT",
]

spike_inst_lower = [field.lower() for field in spike_inst]

""" Spike data trace CSV header """
spike_data = [
    "DRETIRE",
    "DTYPE",
    "DADDR",
    "DSIZE",
    "DATA",
]

spike_data_lower = [field.lower() for field in spike_data]

""" Instruction trace encoder input CSV header (required entries, others may be present) """
encoder_inst_port_required = [
    "itype_0",
    "cause",
    "tval",
    "priv",
    "iaddr_0",
    "context",
    "ctype",
    "iretire_0",
    "ilastsize_0",
]

""" Instruction trace encoder output CSV header """
te_inst = [
    "format",
    "subformat",
    "address",
    "branch",
    "branches",
    "branch_map",
    "branch_count",
    "branch_fmt",
    "context",
    "ecause",
    "ienable",
    "encoder_mode",
    "interrupt",
    "irreport",
    "irdepth",
    "notify",
    "ioptions",
    "privilege",
    "qual_status",
    "time",
    "thaddr",
    "tval",
    "updiscon",
    "denable",
    "dloss",
    "doptions",
]

""" Data trace encoder output CSV header """
# Only handle the unified case
# A combination of the data needed for te_inst (support) and te_data packets
te_data_inst = [
    "msg_type", # Not part of the specification but needed to identify support packets
    "format",
    "subtype",
    "size",
    "diff",
    "op_len",
    "operand",
    "data_len",
    "data",
    "address",
    "addr_msbs",
    "addr_lsbs",
    "subformat",
    "ienable",
    "encoder_mode",
    "qual_status",
    "ioptions",
    "denable",
    "dloss",
    "doptions",
]
