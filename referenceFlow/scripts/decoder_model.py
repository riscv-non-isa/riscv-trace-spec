#!/usr/bin/env python3

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

###########################################################################################
# This is a python model of the instruction trace decoder as described in the RISCV trace
# specification found in
#   https://github.com/riscv-non-isa/riscv-trace-spec
# It is written to be readable and has tried to use the same naming for functions/variables etc.
# as are used in the pseudo code to make it easier to compare the model with the specification.
# The references in the docstrings are to version 1.1.3-Frozen
#
# ****Note that only the baseline algorithm is implemented here.****

import argparse
import csv
import os
import sys
import subprocess
import re

from enum import IntEnum
import configparser

from common import csv_headers
from common.generic import msg_type_t
from common.inst_trace import *
from common.raw_file import RawFile
from common.utils import *

class TeInst:
    """
    Contains the information about a single te_inst packet read from a CSV file
    """
    NO_DATA = '_' # Used to indicate which fields in a CSV are invalid

    def __init__(self, **fields):
        self.__dict__.update(**fields)
        for key, value in self.__dict__.items():
            if value == TeInst.NO_DATA:
                self.__dict__[key] = None # pragma: no cover
            elif key in ("address", "tval"):
                self.__dict__[key] = int(value, 16)
            else:
                self.__dict__[key] = int(value)
        self.format = format_t(self.format)
        if hasattr(self, "subformat"):
            if self.subformat is not None:
                self.subformat = sync_t(self.subformat)
        if hasattr(self, "qual_status"):
            if self.qual_status is not None:
                self.qual_status = qual_status_t(self.qual_status)

    def __repr__(self):
        fields = ", ".join(
            (
                "{}={!r}".format(fieldname, getattr(self, fieldname))
                for fieldname in csv_headers.te_inst
                if hasattr(self, fieldname) and getattr(self, fieldname) is not None
            )
        )
        if hasattr(self, "address"):
            fields += ", address=0x%lx" % self.address
        return "{}({})".format(self.__class__.__name__, fields)

class DecoderHarness:
    """ The top level class to provide a harness for the instruction trace decoder. """

    # RAW reading must be done one packet at a time as the options need to be set before
    # data packets can be decompressed.
    def __init__(self, scf, elf_data):
        expected = []
        if args.expected: # pragma: no cover
            with open(args.expected) as expected_fd:
                for line in expected_fd:
                    entry = line.split()
                    expected.append(int(entry[0], 16))

        is_raw = (os.path.splitext(args.decoder_input)[1] == ".te_inst_raw")
        mode="rb" if is_raw else "r"

        with open(traced, mode="w") as output_fd:
            with open(args.decoder_input, mode=mode) as input_fd:
                decoder = Decoder(scf, output_fd, elf_data, expected)
                if is_raw:
                    rawfile = RawFile(input_fd)
                    while rawfile.has_data():
                        decoder.add(rawfile.process_packet(decoder.create_te_inst))
                    debug_print("npackets %d" % rawfile.npackets)
                else: # pragma: no cover
                    reader = csv.DictReader(input_fd)
                    assert csv_headers.te_inst == reader.fieldnames
                    for entry in reader:
                        decoder.add(TeInst(**entry))

class Decoder:
    """
    This is the main instruction trace decoder class which processes the te_inst packets
    in sequence and reconstructs the instruction trace.
    (See chapter 11 - Decoder, for details of pseudo code which relates to this algorithm)
    """

    def __init__(self, scf, trace_out, elf_data, expected):
        self.scf = scf
        self.trace_out = trace_out
        self.settings = self.init_settings(scf)
        self.elf_data = elf_data
        self.expected = expected

        # Algorithm data
        self.pc = None
        self.last_pc = None
        self.branches = 0
        self.branch_map = 0
        self.stop_at_last_branch = False
        self.inferred_address = False
        self.start_of_trace = True
        self.address = None
        self.return_stack = []
        self.irstack_depth = 0
        rss = self.settings["return_stack_size_p"]
        self.irdepth_width = (
            rss + (1 if rss > 0 else 0) + self.settings["call_counter_size_p"]
        )

        self.flags = {}
        self.i_count = 0
        self.npackets = 0
        self.msb_mask = 1 << (self.settings["iaddress_width_p"] - 1)

    def init_settings(self, scf):
        """
        Initialise the decoder settings from
        - static configuration (hardware settings)
        """
        settings = {}
        # The option settings come from a support te_inst so don't set them here

        for size in ("bpred", "cache", "call_counter", "return_stack"):
            settings["%s_size_p" % size] = int(
                scf["Required Attributes"]["%s_size_p" % size]
            )
        for width in ("context", "ecause", "iaddress", "privilege", "time"):
            settings["%s_width_p" % width] = int(
                scf["Required Attributes"]["%s_width_p" % width]
            )
        settings["iaddress_lsb_p"] = int(scf["Required Attributes"]["iaddress_lsb_p"])
        settings["nocontext_p"] = int(scf["Required Attributes"]["nocontext_p"])
        settings["notime_p"] = int(scf["Required Attributes"]["notime_p"])
        return settings

    def add(self, te_inst):
        self.npackets += 1
        if args.debug:
            debug_print("------- Process te_inst#%d -------\n%s" % (self.npackets, te_inst))
        self.recover_status_fields(te_inst)
        self.process_te_inst(te_inst)

    # Callback to be run by the raw file packet extractor
    def create_te_inst(self, msg_type, packet_length, packet):
        assert msg_type == msg_type_t.TE_INST
        te_inst = {} #"msg_type": msg_type}
        packet.set_output(te_inst)
        packet.get_bits("format", 2)
        if te_inst["format"] == format_t.SYNC:
            self.create_sync(packet, te_inst)
        elif te_inst["format"] == format_t.ADDR:
            self.create_addr(packet, te_inst)
        elif te_inst["format"] == format_t.BRANCH:
            self.create_branch(packet, te_inst)
        elif te_inst["format"] == format_t.EXT: # pragma: no cover
            assert False, "Format 0 not handled yet"
        else: # pragma: no cover
            assert False, "Unknown format %d" % te_inst["format"]
        return TeInst(**te_inst)

    def get_width(self, field, is_conditional=False):
        param = "%s_width_p" % field
        assert param in self.settings
        if is_conditional:
            conditional = "no%s_p" % field
            assert conditional in self.settings
            if self.settings[conditional] == 1:
                return 0
        return self.settings[param]

    def irdepth_bits(self):
        rss = self.settings["return_stack_size_p"]
        return rss + (1 if rss > 0 else 0) + self.settings["call_counter_size_p"]

    def create_sync(self, packet, te_inst):
        packet.get_bits("subformat", 2)
        address_bits = (
            self.settings["iaddress_width_p"] - self.settings["iaddress_lsb_p"]
        )
        tval_bits = self.settings["iaddress_width_p"]

        if te_inst["subformat"] == sync_t.START:
            packet.get_bits("branch", 1)
            packet.get_bits("privilege", self.get_width("privilege"))
            packet.get_bits("time", self.get_width("time", True))
            packet.get_bits("context", self.get_width("context", True))
            packet.get_bits("address", address_bits, is_hex=True)
        elif te_inst["subformat"] == sync_t.TRAP:
            packet.get_bits("branch", 1)
            packet.get_bits("privilege", self.get_width("privilege"))
            packet.get_bits("time", self.get_width("time", True))
            packet.get_bits("context", self.get_width("context", True))
            packet.get_bits("ecause", self.get_width("ecause"))
            packet.get_bits("interrupt", 1)
            packet.get_bits("thaddr", 1)
            packet.get_bits("address", address_bits, is_hex=True)
            if te_inst["interrupt"] != 1:
                packet.get_bits("tval", tval_bits, is_hex=True)
        elif te_inst["subformat"] == sync_t.CONTEXT: # pragma: no cover
            packet.get_bits("privilege", self.get_width("privilege"))
            packet.get_bits("time", self.get_width("time", True))
            packet.get_bits("context", self.get_width("context", True))
        elif te_inst["subformat"] == sync_t.SUPPORT:
            packet.get_bits("ienable", 1)
            packet.get_bits("encoder_mode", 1)
            packet.get_bits("qual_status", 2)
            packet.get_bits("ioptions", 5)
            packet.get_bits("denable", 1)
            packet.get_bits("dloss", 1)
            packet.get_bits("doptions", 4)
        packet.check()

    def create_addr(self, packet, te_inst):
        address_bits = (
            self.settings["iaddress_width_p"] - self.settings["iaddress_lsb_p"]
        )

        packet.get_bits("address", address_bits, is_hex=True)
        packet.get_bits("notify", 1)
        packet.get_bits("updiscon", 1)
        packet.get_bits("irreport", 1)
        packet.get_bits("irdepth", self.irdepth_bits())
        packet.check()

    def create_branch(self, packet, te_inst):
        # Number of bits required by the branch map and whether an address is required
        def branch_map_bits(branches):
            if branches == 0:
                return (31, False)
            if branches == 1:
                return (1, True)
            if branches <= 3:
                return (3, True)
            if branches <= 7:
                return (7, True)
            if branches <= 15:
                return (15, True)
            assert branches < 32
            return (31, True)

        address_bits = (
            self.settings["iaddress_width_p"] - self.settings["iaddress_lsb_p"]
        )
        packet.get_bits("branches", 5)
        branch_bits, has_address = branch_map_bits(te_inst["branches"])
        if has_address:
            # With address
            packet.get_bits("branch_map", branch_bits)
            packet.get_bits("address", address_bits, is_hex=True)
            packet.get_bits("notify", 1)
            packet.get_bits("updiscon", 1)
            packet.get_bits("irreport", 1)
            packet.get_bits("irdepth", self.irdepth_bits())
            packet.check()
        else:
            # No address present
            packet.get_bits("branch_map", branch_bits)
            packet.check()

    def get_instr(self, address):
        return self.elf_data.get(address)

    def set_pc(self, pc):
        assert pc is not None
        self.pc = pc
        if args.debug:
            debug_print("  Set PC: 0x%lx" % self.pc)

    def incr_pc(self, incr):
        assert incr is not None
        if args.debug:
            debug_print("  Incr PC: 0x%lx + 0x%lx" % (self.pc, incr))
        self.set_pc(self.pc + incr)

    def recover_status_fields(self, te_inst):
        # Handle the setting of notify/updiscon/irreport/irdepth to "decompress"
        # the actual settings. Only present in addr packet or branch with addr packet
        self.flags["notify"] = None
        self.flags["updiscon"] = None
        self.flags["irreport"] = None
        if te_inst.format == format_t.ADDR or (
            (te_inst.format == format_t.BRANCH) and te_inst.branches == 31
        ):
            assert te_inst.notify is not None
            assert te_inst.updiscon is not None
            assert te_inst.irreport is not None
            if self.irdepth_width != 0: # pragma: no cover
                assert te_inst.irdepth is not None
            msb = (
                0
                if (self.msb_mask & (te_inst.address << self.settings["iaddress_lsb_p"]))
                == 0
                else 1
            )
            self.flags["notify"] = te_inst.notify != msb
            self.flags["updiscon"] = te_inst.updiscon != te_inst.notify
            self.flags["irreport"] = te_inst.irreport != te_inst.updiscon

    def process_te_inst(self, te_inst):
        if te_inst.format == format_t.SYNC:
            if te_inst.subformat == sync_t.SUPPORT:
                self.process_support(te_inst)
                return
            if te_inst.subformat == sync_t.CONTEXT: # pragma: no cover
                return
            if te_inst.subformat == sync_t.TRAP:
                self.report_trap(te_inst)
                if not te_inst.interrupt:
                    self.report_epc(self.exception_address(te_inst))
                if te_inst.thaddr == 0:
                    return

            self.inferred_address = False
            self.address = te_inst.address << self.settings["iaddress_lsb_p"]
            assert self.address != 0, te_inst.address
            if te_inst.subformat == sync_t.TRAP or self.start_of_trace:
                self.branches = 0
                self.branch_map = 0
            if self.get_instr(self.address).is_branch:
                self.branch_map |= te_inst.branch << self.branches
                self.branches += 1
            if te_inst.subformat == sync_t.START and not self.start_of_trace:
                self.follow_execution_path(self.address, te_inst)
            else:
                self.set_pc(self.address)
                self.report_pc(self.pc)
                self.last_pc = self.pc
            self.start_of_trace = False
            self.irstack_depth = 0
        else:
            assert not self.start_of_trace
            if te_inst.format == format_t.ADDR or te_inst.branches != 0:
                self.stop_at_last_branch = False
                address = te_inst.address << self.settings["iaddress_lsb_p"]
                if self.settings["full-address"]:
                    self.address = address
                else:
                    self.address += twoscomp(address, self.settings["iaddress_width_p"])
            if te_inst.format == format_t.BRANCH:
                self.stop_at_last_branch = (te_inst.branches == 0)
                # Branch map will contain <= 1 branch (1 if last reported instruction was a branch)
                self.branch_map |= (te_inst.branch_map << self.branches)
                if te_inst.branches == 0:
                    self.branches += 31
                else:
                    self.branches += te_inst.branches
            self.follow_execution_path(self.address, te_inst)

    def process_support(self, te_inst):
        """
        Derive the options from a te_inst support packet.
        Note that the order and the set of options is not dictated by the specification
        and is implementation specific.
        """
        options = te_inst.ioptions
        # From decoder-algorithm.h
        # define TE_OPTIONS_IMPLICIT_RETURN      (1u)
        # define TE_OPTIONS_IMPLICIT_EXCEPTION   (1u << 1)
        # define TE_OPTIONS_FULL_ADDRESS         (1u << 2)
        # define TE_OPTIONS_JUMP_TARGET_CACHE    (1u << 3)
        # define TE_OPTIONS_BRANCH_PREDICTION    (1u << 4)
        # define TE_OPTIONS_NUM_BITS             (5u)    /* number of bits to send te_options_t */
        self.settings["implicit-return"] = (options & 1) == 1
        self.settings["implicit-except"] = (options >> 1) & 1 == 1
        self.settings["full-address"] = (options >> 2) & 1 == 1
        self.settings["jump-target-cache"] = (options >> 3) & 1 == 1
        self.settings["branch-prediction"] = (options >> 4) & 1 == 1

        debug_print("implicit-return:%s" % self.settings["implicit-return"])
        debug_print("implicit-except:%s" % self.settings["implicit-except"])
        debug_print("full-address:%s" % self.settings["full-address"])
        debug_print("jump-target-cache:%s" % self.settings["jump-target-cache"])
        debug_print("branch-prediction:%s" % self.settings["branch-prediction"])

        if te_inst.qual_status != qual_status_t.NO_CHANGE:
            self.start_of_trace = True  # Trace ended, so get ready to start again

            if te_inst.qual_status == qual_status_t.ENDED_NTR and self.inferred_address: # pragma: no cover
                local_previous_address = self.pc
                self.inferred_address = False
                while True:
                    local_stop_here = self.next_pc(local_previous_address)
                    self.report_pc(self.pc)
                    if local_stop_here:
                        return

    def follow_execution_path(self, address, te_inst):
        def branch_limit():
            return 1 if self.get_instr(self.pc).is_branch else 0

        if args.debug:
            debug_print("follow_execution_path 0x%lx" % address)
        local_previous_address = self.pc
        local_stop_here = False
        while True:
            if self.inferred_address:
                debug_print("  Inferred address: 0x%lx" % local_previous_address)
                local_stop_here = self.next_pc(local_previous_address)
                self.report_pc(self.pc)
                if local_stop_here:
                    self.inferred_address = False
            else:
                debug_print("  Not inferred address: 0x%lx" % address)
                local_stop_here = self.next_pc(address)
                self.report_pc(self.pc)
                if (
                    self.branches == 1
                    and self.get_instr(self.pc).is_branch
                    and self.stop_at_last_branch
                ):
                    # Reached final branch - stop here (do not follow to next instruction as
                    # we do not yet know whether it retires)
                    self.stop_at_last_branch = False
                    return
                if local_stop_here:
                    # Reached reported address following an uninferable discontinuity - stop here
                    # Check all branches processed (except 1 if this instruction is a branch)
                    assert (
                        self.branches <= branch_limit()
                    ), "Error: unprocessed branches"
                    return
                if (
                    te_inst.format != format_t.SYNC
                    and self.pc == address
                    and not self.stop_at_last_branch
                    and self.flags["notify"]
                    and self.branches == branch_limit()
                ): # pragma: no cover
                    return
                if (
                    te_inst.format != format_t.SYNC
                    and self.pc == address
                    and not self.stop_at_last_branch
                    and not self.is_uninferable_discon(self.get_instr(self.last_pc))
                    and not self.flags["updiscon"]
                    and self.branches == branch_limit()
                    and (
                        not self.flags["irreport"]
                        or te_inst.irdepth == self.irstack_depth
                    )
                ):
                    # All branches processed, and reached reported address, but not as an
                    # uninferable jump target
                    # Stop here for now, though flag indicates this may not be
                    # final retired instruction
                    self.inferred_address = True
                    return
                if (
                    te_inst.format == format_t.SYNC
                    and self.pc == address
                    and self.branches == branch_limit()
                ):
                    # All branches processed, and reached reported address
                    return

    def next_pc(self, address):
        local_instr = self.get_instr(self.pc)
        local_this_pc = self.pc
        local_stop_here = False

        if args.debug:
            debug_print("  next_pc(0x%lx)" % address)
        if self.is_inferable_jump(local_instr):
            assert local_instr.imm is not None, local_instr
            self.incr_pc(local_instr.imm)
            # Not in the spec but stops an infinite loop
            if local_instr.imm == 0: # pragma: no cover
                local_stop_here = True
        elif self.is_sequential_jump(local_instr, self.last_pc): # pragma: no cover
            self.set_pc(self.sequential_jump_target(self.pc, self.last_pc))
        elif self.is_implicit_return(local_instr): # pragma: no cover
            self.set_pc(self.pop_return_stack())
        elif self.is_uninferable_discon(local_instr):
            assert (
                not self.stop_at_last_branch
            ), "Error: Unexpected uninferable discontinuity"
            self.set_pc(address)
            local_stop_here = True
        elif self.is_taken_branch(local_instr):
            assert local_instr.imm is not None, local_instr
            self.incr_pc(local_instr.imm)
            # Not in the spec but stops an infinite loop
            if local_instr.imm == 0: # pragma: no cover
                local_stop_here = True
        else:
            self.incr_pc(local_instr.size)

        if self.is_call(local_instr):
            self.push_return_stack(local_this_pc)

        self.last_pc = local_this_pc

        return local_stop_here

    def is_taken_branch(self, instr):
        if not instr.is_branch:
            return False
        assert self.branches != 0, "Error: cannot resolve branch"
        local_taken = (self.branch_map & 1) == 0
        self.branches -= 1
        self.branch_map = self.branch_map >> 1
        return local_taken

    def is_inferable_jump(self, instr):
        if instr.opcode == "jalr":
            assert instr.rs1 is not None
        return instr.opcode in ("jal", "c.jal", "c.j") or (
            instr.opcode == "jalr" and instr.rs1 == 0
        )

    def is_implicit_return(self, instr):
        return False

    def is_sequential_jump(self, instr, last_pc):
        return False

    def sequential_jump_target(self, pc, last_pc): # pragma: no cover
        return None

    def is_uninferable_jump(self, instr):
        return instr.opcode in ("c.jalr", "c.jr") or (
            instr.opcode == "jalr" and instr.rs1 != 0
        )

    def is_uninferable_discon(self, instr):
        return self.is_uninferable_jump(instr) or instr.opcode in (
            "uret",
            "sret",
            "mret",
            "dret",
            "ecall",
            "ebreak",
            "c.ebreak",
        )

    # Determine if instruction is a call
    # - excludes tail calls as they do not push an address onto the return stack
    def is_call(self, instr):
        return (
            instr.opcode in ("c.jalr", "c.jal")
            or (instr.opcode == "jalr" and instr.rd == 1)
            or (instr.opcode == "jal" and instr.rd == 1)
        )

    def push_return_stack(self, address):
        pass

    def pop_return_stack(self): # pragma: no cover
        return None

    def exception_address(self, te_inst):
        local_instr = self.get_instr(self.pc)
        local_address = None

        if self.is_uninferable_discon(local_instr) and te_inst.thaddr == 0:
            local_address = te_inst.address
        elif local_instr.opcode in ("ecall", "ebreak", "c.ebreak"):
            local_address = self.pc
        else:
            local_address = self.next_pc(self.pc)
        debug_print("  exception_address: 0x%lx thaddr: %d" % (local_address, te_inst.thaddr))
        return local_address

    def report_trap(self, te_inst):
        if args.debug:
            if te_inst.interrupt:
                debug_print("  TRAP(interrupt): ecause: %d" % te_inst.ecause)
            else:
                debug_print("  TRAP: ecause: %d tval: 0x%lx" % (te_inst.ecause, te_inst.tval))

    def report_pc(self, address):
        debug_print("report_pc[%d] --------------> 0x%lx" % (self.i_count, address))
        self.trace_out.write("%lx\n" % address)
        if self.i_count < len(self.expected): # pragma: no cover
            if self.expected[self.i_count] != address:
                print(
                    "Error: expected 0x%lx decoded 0x%lx" % (self.expected[self.i_count], address)
                )
                exit(1)
        self.i_count += 1

    def report_epc(self, address):
        if args.debug:
            debug_print("  EPC: 0x%lx" % address)


class Instruction:
    """
    A representation of a single instruction using the text taken from objdump.
    It "disassembles" the instruction where necessary to allow the decoder to determine
    various attributes of the instruction.
    Note that it is NOT a full disassembler.
    """
    R_TYPE = (
        "add",
        "addw",
        "sub",
        "subw",
        "xor",
        "or",
        "and",
        "sll",
        "sllw",
        "srl",
        "srlw",
        "sra",
        "sraw",
        "slt",
        "sltu",
        "mul",
        "mulh",
        "mulhsu",
        "mulhu",
        "div",
        "divu",
        "rem",
        "remu",
        "mulw",
        "divw",
        "divuw",
        "remw",
        "remuw",
    )
    I_TYPE = (
        "addi",
        "addiw",
        "xori",
        "ori",
        "andi",
        "slli",
        "slliw",
        "srli",
        "srliw",
        "srai",
        "sraiw",
        "slti",
        "sltiu",
        "lb",
        "lh",
        "lw",
        "lwu",
        "ld",
        "lbu",
        "lhu",
        "jalr",
    )
    CSR_TYPE = ("csrrw", "csrrs", "csrrc")
    ICSR_TYPE = ("csrrwi", "csrrsi", "csrrci")
    S_TYPE = ("sb", "sh", "sw", "sd")
    B_TYPE = ("beq", "bne", "blt", "bge", "bltu", "bgeu")
    U_TYPE = ("lui", "auipc")
    J_TYPE = "jal"

    SYS_TYPE = (
        "ecall",
        "ebreak",
        "mret",
        "sret",
        "uret",
        "fence",
        "fence.i",
        "sfence.vma",
        "wfi",
    )

    CR_TYPE = ("c.jr", "c.mv", "c.ebreak", "c.jalr", "c.add")
    CI_TYPE = (
        "c.nop",
        "c.addi",
        "c.addiw",
        "c.li",
        "c.addi16sp",
        "c.lui",
        "c.srli",
        "c.srli64",
        "c.srai",
        "c.srai64",
        "c.andi",
        "c.slli",
        "c.slli64",
        "c.fldsp",
        "c.lqsp",
        "c.lwsp",
        "c.flwsp",
        "c.ldsp",
    )
    CSS_TYPE = ("c.fsdsp", "c.sqsp", "c.swsp", "c.fswsp", "c.sdsp")
    CIW_TYPE = "c.addi4spn"
    CL_TYPE = (
        "c.fld",
        "c.lq",
        "c.lw",
        "c.flw",
        "c.ld",
    )
    CS_TYPE = ("c.fsd", "c.sq", "c.sw", "c.fsw", "c.sd")
    CA_TYPE = ("c.sub", "c.xor", "c.or", "c.and", "c.subw", "c.addw")
    CB_TYPE = ("c.beqz", "c.bnez")
    CJ_TYPE = ("c.j", "c.jal")

    UNIMP_TYPE = "c.unimp"

    # Some instructions use e.g 5(a0) syntax, so need to split this out
    PATTERN = re.compile("([-]?[0-9]*)\(([a-z]+[0-9]*)\)")

    def __init__(self, address, fields):
        self.address = address
        self.fields = fields
        self.binary = fields[1].strip()
        assert len(self.binary) in (4, 8), fields  # 4 or 8 hex digits i.e. 2 or 4 bytes
        self.size = len(self.binary) >> 1
        self.opcode = fields[2]
        self.args = []
        if len(fields) > 3:
            self.args = self.convert_args(fields[3])

        self.r_type = self.opcode in Instruction.R_TYPE
        self.i_type = self.opcode in Instruction.I_TYPE
        self.csr_type = self.opcode in Instruction.CSR_TYPE
        self.icsr_type = self.opcode in Instruction.ICSR_TYPE
        self.s_type = self.opcode in Instruction.S_TYPE
        self.b_type = self.opcode in Instruction.B_TYPE
        self.u_type = self.opcode in Instruction.U_TYPE
        self.j_type = self.opcode in Instruction.J_TYPE

        self.f_type = self.opcode.startswith("f")
        self.atomic_type = (
            self.opcode.startswith("amo")
            or self.opcode.startswith("lr")
            or self.opcode.startswith("sc")
        )
        self.sys_type = self.opcode in Instruction.SYS_TYPE

        self.cr_type = self.opcode in Instruction.CR_TYPE
        self.ci_type = self.opcode in Instruction.CI_TYPE
        self.css_type = self.opcode in Instruction.CSS_TYPE
        self.ciw_type = self.opcode in Instruction.CIW_TYPE
        self.cl_type = self.opcode in Instruction.CL_TYPE
        self.cs_type = self.opcode in Instruction.CS_TYPE
        self.ca_type = self.opcode in Instruction.CA_TYPE
        self.cb_type = self.opcode in Instruction.CB_TYPE
        self.cj_type = self.opcode in Instruction.CJ_TYPE

        self.unimp_type = self.opcode in Instruction.UNIMP_TYPE
        assert (
            self.r_type
            or self.i_type
            or self.csr_type
            or self.icsr_type
            or self.s_type
            or self.b_type
            or self.u_type
            or self.j_type
            or self.f_type
            or self.atomic_type
            or self.sys_type
            or self.cr_type
            or self.ci_type
            or self.css_type
            or self.ciw_type
            or self.cl_type
            or self.cs_type
            or self.ca_type
            or self.cb_type
            or self.cj_type
            or self.unimp_type
        ), fields
        self.is_branch = self.b_type or self.cb_type
        self.is_branch_compressed = self.cb_type
        self.imm = None
        self.rs1 = None
        self.rs2 = None
        self.rd = None

        if self.b_type:
            self.set_rs1(self.reg(self.args[0]))
            self.set_rs2(self.reg(self.args[1]))
            self.set_imm(int(self.args[2], 16) - self.address)
        if self.cb_type:
            self.set_rs1(self.reg(self.args[0]))
            self.set_imm(int(self.args[1], 16) - self.address)
        if self.r_type:
            self.set_rd(self.reg(self.args[0]))
            self.set_rs1(self.reg(self.args[1]))
            self.set_rs2(self.reg(self.args[2]))
        if self.i_type:
            self.set_rd(self.reg(self.args[0]))
            self.set_rs1(self.reg(self.args[1]))
            self.set_imm(int(self.args[2], 16))
        if self.j_type or self.u_type:
            self.set_rd(self.reg(self.args[0]))
            self.set_imm(int(self.args[1], 16) - self.address)
        if self.cj_type:
            self.set_imm(int(self.args[0], 16) - self.address)

    def set_imm(self, imm):
        assert self.imm is None
        self.imm = imm

    def set_rs1(self, rs1):
        assert self.rs1 is None
        self.rs1 = rs1

    def set_rs2(self, rs2):
        assert self.rs2 is None
        self.rs2 = rs2

    def set_rd(self, rd):
        assert self.rd is None
        self.rd = rd

    def __repr__(self):
        str = "%s (%d bytes):" % (self.opcode, self.size)
        if self.imm is not None:
            str += " imm=0x%lx" % self.imm
        if self.rs1 is not None:
            str += " rs1=%d" % self.rs1
        if self.rs2 is not None:
            str += " rs2=%d" % self.rs2
        if self.rd is not None:
            str += " rd=%d" % self.rd
        return str + " RAW[%s]" % " ".join(self.fields)

    def convert_args(self, arg_str):
        args = []
        for part in re.split(",| ", arg_str):
            m = Instruction.PATTERN.match(part)
            if m:
                assert len(m.groups()) == 2
                args.append(m.groups()[1])
                if m.groups()[0] != "":
                    args.append(m.groups()[0])
            else:
                args.append(part)
        return args

    ABI_NAMES = ["zero", "ra", "sp", "gp", "tp"]

    def reg(self, arg):
        if arg in Instruction.ABI_NAMES:
            return Instruction.ABI_NAMES.index(arg)
        if arg == "fp": # pragma: no cover
            return 8
        abi_id = arg[0]
        if abi_id == "f": # pragma: no cover
            idx = int(arg[2:])
            return None

        idx = int(arg[1:])
        if abi_id == "t":
            offset = 5 if idx < 3 else 25
        elif abi_id == "s":
            offset = 8 if idx < 2 else 16
        elif abi_id == "a":
            offset = 10
        else: # pragma: no cover
            print("Unknown register name %s" % arg)
        return offset + idx


class ElfData:
    """
    A class to manage the elf files required by the decoder. It adds the preset startup code
    required by the spike simulator as this is not present in the user's elf files.
    """
    def __init__(self, elf_files, use_rv32_isa):
        # Spike startup code
        self.instr = {}
        self.add("\t".join(["1000:", "00000297", "auipc", "t0,0x0"]))
        self.add("\t".join(["1004:", "02028593", "addi", "a1,t0,32 # 0x1020"]))
        self.add("\t".join(["1008:", "f1402573", "csrrs", "a0,mhartid"]))
        if use_rv32_isa:
            self.add("\t".join(["100c:", "0182a283", "ld", "t0,24(t0)"]))
        else:
            self.add("\t".join(["100c:", "0182b283", "ld", "t0,24(t0)"]))
        self.add("\t".join(["1010:", "8282", "c.jr", "t0"]))

        for elf in elf_files.split():
            self.elf_extract(elf)

    def elf_extract(self, elf_path):
        riscv_toolchain = os.environ.get("RISCV_TOOLCHAIN")
        if riscv_toolchain is None: # pragma: no cover
            riscv_toolchain = "%s/../" % sys.path[0]
        objdump_path = "%s/bin/riscv64-unknown-elf-objdump" % riscv_toolchain
        if not os.path.exists(objdump_path): # pragma: no cover
            print("Unable to find the executable %s" % objdump_path)
        # Use the arguments for subprocess.run that work pre python 3.7 i.e. not capture_output
        # no-aliases makes sure that pseudo instructions aren't used
        objdump = subprocess.run(
            [objdump_path, "-M", "no-aliases", "-d", elf_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True
        )
        for line in objdump.stdout.splitlines():
            self.add(line)
        print("Read %d instructions" % len(self.instr))

    def add(self, line):
        fields = line.split("\t")
        if len(fields) < 3:
            return
        address = int(fields[0].strip(" ").rstrip(":"), 16)
        assert address not in self.instr, "0x%lx already added" % address
        self.instr[address] = Instruction(address, fields)
        if args.debug:
            debug_print("0x%lx: %s" % (address, self.instr[address]))

    def get(self, address):
        if address not in self.instr: # pragma: no cover
            print("Error: Instruction at address 0x%lx not found" % address)
            exit(1)
        return self.instr[address]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--static_cfg", help="Static Config file", type=str)
    parser.add_argument("-u", "--user_cfg", help="User Config file", type=str)
    parser.add_argument("--debug", help="Debug flag", action="store_true")
    parser.add_argument("--expected", help="Trace file expected", type=str)
    parser.add_argument("-i", "--decoder-input", help="Input te_inst file", type=str)
    args = parser.parse_args()
    init_debug(args.debug)

    if not args.static_cfg or not args.user_cfg: # pragma: no cover
        print("Static and User config files required")
        exit(1)
    scf = configparser.ConfigParser()
    scf.read(args.static_cfg)
    ucf = configparser.ConfigParser()
    ucf.read(args.user_cfg)

    elf_data = ElfData(
        ucf["required"]["object-files"], ucf["flags"]["use-rv32-isa"] == "true"
    )

    if not args.decoder_input: # pragma: no cover
        print("Input te_inst file required")
        exit(1)

    if not os.path.exists(args.decoder_input): # pragma: no cover
        print("Unable to find the input file %s" % args.decoder_input)
        exit(1)

    traced = (
        os.path.splitext(os.path.basename(args.decoder_input))[0] + ".decoder.trace"
    )

    harness = DecoderHarness(scf, elf_data)
