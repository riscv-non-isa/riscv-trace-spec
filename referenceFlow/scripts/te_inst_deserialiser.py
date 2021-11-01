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

# This is a python model of the deserialisation of the te_inst information that is produced
# by the instruction trace encoder as described in the RISCV trace specification found in
#   https://github.com/riscv-non-isa/riscv-trace-spec
# It is written to be readable and has tried to use the same naming as used in the specification.
# Only minor changes have been made to make it run more efficiently.

import argparse
import csv
import os
import struct


from collections import OrderedDict
from enum import IntEnum
import configparser

from common import csv_headers
from common.generic import msg_type_t
from common.inst_trace import *
from common.raw_file import RawFile
from common.utils import *

class Writer:
    NO_DATA = '_' # Used to indicate which fields in a CSV are invalid

    def __init__(self, scf, ucf, te_out):
        self.te_out = te_out
        self.scf = scf
        self.ucf = ucf
        self.te_inst = OrderedDict({key: None for key in csv_headers.te_inst})
        self.settings = self.init_settings()

    def reset(self):
        for key in self.te_inst.keys():
            self.te_inst[key] = None

    def init_settings(self):
        settings = {}
        for size in ("bpred", "cache", "call_counter", "return_stack"):
            settings["%s_size_p" % size] = int(
                self.scf["Required Attributes"]["%s_size_p" % size]
            )
        for width in ("context", "ecause", "iaddress", "privilege", "time"):
            settings["%s_width_p" % width] = int(
                self.scf["Required Attributes"]["%s_width_p" % width]
            )
        settings["iaddress_lsb_p"] = int(
            self.scf["Required Attributes"]["iaddress_lsb_p"]
        )
        settings["nocontext_p"] = int(self.scf["Required Attributes"]["nocontext_p"])
        settings["notime_p"] = int(self.scf["Required Attributes"]["notime_p"])
        return settings

    def send_te_inst(self):
        # Check that no extra fields have been added as it's just a dict
        assert len(self.te_inst) == len(csv_headers.te_inst), "%s %s" % (
            self.te_inst.keys(),
            csv_headers.te_inst,
        )
        self.te_out.writerow([
            Writer.NO_DATA if self.te_inst[key] is None else self.te_inst[key]
            for key in self.te_inst.keys()
        ])

        self.reset()

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

    def create_sync(self, packet):
        packet.get_bits("subformat", 2)
        address_bits = (
            self.settings["iaddress_width_p"] - self.settings["iaddress_lsb_p"]
        )
        tval_bits = self.settings["iaddress_width_p"]

        if self.te_inst["subformat"] == sync_t.START:
            packet.get_bits("branch", 1)
            packet.get_bits("privilege", self.get_width("privilege"))
            packet.get_bits("time", self.get_width("time", True))
            packet.get_bits("context", self.get_width("context", True))
            packet.get_bits("address", address_bits, is_hex=True)
        elif self.te_inst["subformat"] == sync_t.TRAP:
            packet.get_bits("branch", 1)
            packet.get_bits("privilege", self.get_width("privilege"))
            packet.get_bits("time", self.get_width("time", True))
            packet.get_bits("context", self.get_width("context", True))
            packet.get_bits("ecause", self.get_width("ecause"))
            packet.get_bits("interrupt", 1)
            packet.get_bits("thaddr", 1)
            packet.get_bits("address", address_bits, is_hex=True)
            if self.te_inst["interrupt"] != 1:
                packet.get_bits("tval", tval_bits, is_hex=True)
        elif self.te_inst["subformat"] == sync_t.CONTEXT:
            packet.get_bits("privilege", self.get_width("privilege"))
            packet.get_bits("time", self.get_width("time", True))
            packet.get_bits("context", self.get_width("context", True))
        elif self.te_inst["subformat"] == sync_t.SUPPORT:
            packet.get_bits("ienable", 1)
            packet.get_bits("encoder_mode", 1)
            packet.get_bits("qual_status", 2)
            packet.get_bits("ioptions", 5)

        packet.check()

    def create_addr(self, packet):
        address_bits = (
            self.settings["iaddress_width_p"] - self.settings["iaddress_lsb_p"]
        )

        packet.get_bits("address", address_bits, is_hex=True)
        packet.get_bits("notify", 1)
        packet.get_bits("updiscon", 1)
        packet.get_bits("irreport", 1)
        packet.get_bits("irdepth", self.irdepth_bits())
        packet.check()

    def create_branch(self, packet):
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
        branch_bits, has_address = branch_map_bits(self.te_inst["branches"])
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

    def create_te_inst(self, msg_type, packet_length, packet):
        assert msg_type == msg_type_t.TE_INST
        packet.set_output(self.te_inst)
        packet.get_bits("format", 2)
        if self.te_inst["format"] == format_t.SYNC:
            self.create_sync(packet)
        elif self.te_inst["format"] == format_t.ADDR:
            self.create_addr(packet)
        elif self.te_inst["format"] == format_t.BRANCH:
            self.create_branch(packet)
        elif self.te_inst["format"] == format_t.EXT:
            assert False, "Format 0 not handled yet"
        else:
            assert False, "Unknown format %d" % self.te_inst["format"]

        self.send_te_inst()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--static_cfg", help="Static Config file", type=str)
    parser.add_argument("-u", "--user_cfg", help="User Config file", type=str)
    parser.add_argument("--debug", help="Debug flag", action="store_true")
    parser.add_argument("input", help="Input te_inst raw file", type=str)
    args = parser.parse_args()
    init_debug(args.debug)

    if not args.static_cfg or not args.user_cfg:
        print("Static and User config files required")
        exit(1)
    scf = configparser.ConfigParser()
    scf.read(args.static_cfg)
    ucf = configparser.ConfigParser()
    ucf.read(args.user_cfg)

    decoder_input = args.input
    if not os.path.exists(decoder_input):
        print("Unable to find the input file %s" % decoder_input)
        exit(1)

    te_inst = os.path.splitext(os.path.basename(decoder_input))[0] + ".te_inst_csv"

    with open(te_inst, mode="w") as output_fd:
        output_csv = csv.writer(
            output_fd, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL
        )

        output_csv.writerow(csv_headers.te_inst)
        with open(decoder_input, mode="rb") as raw_fd:
            # Read the te_inst raw data and produce the CSV equivalent
            rawfile = RawFile(raw_fd)
            writer = Writer(scf, ucf, output_csv)
            while rawfile.has_data():
                rawfile.process_packet(writer.create_te_inst)
            debug_print("npackets %d" % rawfile.npackets)
