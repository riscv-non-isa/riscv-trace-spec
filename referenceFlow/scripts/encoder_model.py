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
# This is a python model of the instruction trace encoder as described in the RISCV trace
# specification found in
#   https://github.com/riscv-non-isa/riscv-trace-spec
# It is written to be readable and has tried to use the same naming for flags etc. to
# make it easier to compare the model with the specification.
# The references in the docstrings are to version 1.1.3-Frozen October 27th 2021
#
# ****Note that only the baseline algorithm is implemented here.****

import argparse
import csv
import os

from collections import OrderedDict
import configparser

from common import csv_headers
from common.generic import msg_type_t
from common.inst_trace import *
from common.raw_write import RawWrite
from common.utils import *

class Instruction:
    """
    Contains the information about a single instruction - note that only the single
    retirement case is supported.
    """
    def __init__(self, in_idx, row, qualified=True):
        self.itype_0 = itype_t(int(row[in_idx["itype_0"]]))
        self.cause = int(row[in_idx["cause"]])
        self.tval = int(row[in_idx["tval"]], 16)
        self.priv = int(row[in_idx["priv"]])
        self.iaddr_0 = int(row[in_idx["iaddr_0"]], 16)
        self.iretire_0 = int(row[in_idx["iretire_0"]])
        self.ilastsize_0 = int(row[in_idx["ilastsize_0"]])

        self.context = int(row[in_idx["context"]]) if "context" in in_idx else None
        self.time = int(row[in_idx["time"]]) if "time" in in_idx else None
        self.ctype = ctype_t(int(row[in_idx["ctype"]])) if "ctype" in in_idx else None
        self.sijump_0 = int(row[in_idx["sijump_0"]]) if "sijump_0" in in_idx else None

        # Fake entry to hold qualification status
        self.qualified = qualified

class Pipeline:
    """
    Represents the 3 stage pipeline used by the instruction trace encoder
    (See chapter 9 - Reference Compressed Branch Trace Algorithm)
    """
    PREVIOUS = 0
    CURRENT = 1
    NEXT = 2

    def __init__(self, in_header):
        self.in_header = in_header
        self.in_idx = {}
        self.init_instruction_elements()
        self.inst = [
            Instruction(self.in_idx, ["0"] * len(in_header), False),
            Instruction(self.in_idx, ["0"] * len(in_header), False),
            Instruction(self.in_idx, ["0"] * len(in_header), False),
        ]

    def init_instruction_elements(self):
        """
        Creates an index lookup table from the CSV header line to increase performance of
        reading the CSV input data
        """
        required = [
            "itype_0",
            "cause",
            "tval",
            "priv",
            "iaddr_0",
            "iretire_0",
            "ilastsize_0",
        ]
        optional = ["context", "time", "ctype", "sijump_0"]
        # Check all required are present
        for field in required:
            assert field in self.in_header, field

        # Check all fields in the header are in the lists
        for field in self.in_header:
            assert field in required or field in optional, field

        for field in required:
            self.in_idx[field] = self.in_header.index(field)
        for field in optional:
            if field in self.in_header:
                self.in_idx[field] = self.in_header.index(field)

    def add(self, entry):
        """ Add a single CSV entry to the pipeline """
        inst = Instruction(self.in_idx, entry)
        self.add_instruction(inst)

    def add_instruction(self, inst):
        """ Add a single Instruction object to the pipeline """
        self.inst[Pipeline.PREVIOUS] = self.inst[Pipeline.CURRENT]
        self.inst[Pipeline.CURRENT] = self.inst[Pipeline.NEXT]
        self.inst[Pipeline.NEXT] = inst
        if args.debug:
            debug_print(
                "Pipeline:next=0x%lx curr=0x%lx prev=0x%lx"
                % (
                    self.inst[Pipeline.NEXT].iaddr_0,
                    self.inst[Pipeline.CURRENT].iaddr_0,
                    self.inst[Pipeline.PREVIOUS].iaddr_0,
                )
            )

    def __repr__(self):
        pipeline = []
        if self.inst[Pipeline.NEXT].qualified:
            pipeline.append("next=%s" % as_hex(self.inst[Pipeline.NEXT].iaddr_0, 64))
        if self.inst[Pipeline.CURRENT].qualified:
            pipeline.append("curr=%s" % as_hex(self.inst[Pipeline.CURRENT].iaddr_0, 64))
        if self.inst[Pipeline.PREVIOUS].qualified:
            pipeline.append(
                "prev=%s" % as_hex(self.inst[Pipeline.PREVIOUS].iaddr_0, 64)
            )
        return " ".join(pipeline)


class AddressHandler:
    """
    Holds the information about representing addresses. The static configuration
    determines the address width and address lsb. Whether to use full addresses comes from
    the user configuration.
    """
    def __init__(self, width, lsb, use_full_address):
        self.msb_shift = width - 1
        self.msb_mask = 1 << self.msb_shift
        self.lsb = lsb
        self.use_full_address = use_full_address
        self.last_address = None

    def get(self, address):
        if self.use_full_address:
            return address
        assert self.last_address is not None
        return (address - self.last_address) >> self.lsb

    def get_full(self, address):
        return address >> self.lsb

    def get_msb(self, address):
        if self.use_full_address:
            return (address & self.msb_mask) >> self.msb_shift
        return ((address - self.last_address) & self.msb_mask) >> self.msb_shift

    def set_last_address(self, address):
        """
        Make a record of the last address sent by the encoder for use in constructing
        differential addresses
        """
        self.last_address = address


class EncoderHarness:
    """ The top level class to provide a harness for the instruction trace encoder. """
    def __init__(self, scf, ucf, encoder_input):
        # Only handle the single retirement case
        te_inst = os.path.splitext(os.path.basename(encoder_input))[0] + ".te_inst"
        te_inst_raw = te_inst + "_raw"
        te_inst_annotated = te_inst + "_annotated"

        with open(te_inst, mode="w") as output_fd, open(
            te_inst_raw, mode="w+b"
        ) as raw_fd, open(te_inst_annotated, mode="w") as annotated_fd:
            output_csv = csv.writer(
                output_fd, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL
            )

            output_csv.writerow(csv_headers.te_inst)
            with open(encoder_input) as input_fd:
                reader = csv.reader(input_fd)
                found_header = False
                for entry in reader:
                    if not found_header:
                        found_header = True
                        # The fields that are present are not fixed. There is a set of required
                        # fields, but others may be present depending on the settings in the scf.
                        for field in csv_headers.encoder_inst_port_required:
                            assert field in entry, "%s %s" % (field, csv_headers.encoder_inst_port_required)
                        pipeline = Pipeline(entry)
                        encoder = Encoder(
                            pipeline,
                            scf,
                            ucf,
                            output_csv,
                            raw_fd,
                            annotated_fd,
                        )
                        continue
                    encoder.add(entry)

            encoder.close()


class Encoder:
    """
    This is the main instruction trace encoder class which interacts with the instruction
    pipeline and produces encoded te_inst packets when required.
    (See chapter 9 - Reference Compressed Branch Trace Algorithm)
    It is capable of producing 3 forms of te_inst output:
    - CSV
    - byte stream (raw)
    - annotated with the instruction stream for debug purposes (switched off by default)
    """
    MAX_BRANCHES = 31
    NO_DATA = '_' # Used to indicate which fields in a CSV are invalid

    def __init__(
        self, pipeline, scf, ucf, te_out, te_out_raw, te_annotated
    ):
        self.pipeline = pipeline
        self.scf = scf
        self.ucf = ucf
        self.settings = self.init_settings(scf, ucf)
        self.option_bits = None
        self.ioptions = self.init_options()
        self.te_out = te_out
        self.te_out_raw = te_out_raw
        self.te_annotated = te_annotated
        self.te_stats = {
            "f0": 0,
            "f1": 0,
            "f2": 0,
            "f30": 0,
            "f31": 0,
            "f32": 0,
            "f33": 0,
        }
        self.te_stats["npackets"] = 0
        self.te_stats["nbits_compressed"] = 0
        self.te_stats["nbits"] = 0
        self.i_count = 0
        self.te_inst = OrderedDict({key: None for key in csv_headers.te_inst})
        self.address_handler = AddressHandler(
            self.settings["iaddress_width_p"],
            self.settings["iaddress_lsb_p"],
            self.settings["full-address"],
        )
        self.raw = None

        self.exceptions = (itype_t.EXCEPTION, itype_t.INTERRUPT)
        self.updiscons = [
            itype_t.UNINFERABLE_JUMP,  # Used by itype_width = 3
            itype_t.UNINFERABLE_CALL,  # Remainder are itype_width = 4
            itype_t.UNINFERABLE_TAIL_CALL,
            itype_t.OTHER_UNINFERABLE_JUMP,
        ]

        if not self.settings["implicit-return"]:
            self.updiscons.append(itype_t.RETURN)
            self.updiscons.append(itype_t.CO_ROUTINE_SWAP)
        self.updiscons = tuple(self.updiscons)

        # Algorithm data
        self.flags = {}
        self.branches = 0
        self.branch_map = []
        resync_max = self.settings["resync-max"]
        self.resync_max = 1 << (resync_max + 4)
        self.resync_count = 0
        self.trap_reported = False

        # Optional extensions - Not currently implemented for baseline
        self.pbc = 0

        self.reasons = []
        self.has_sent_te_inst = False

        # Before doing anything a support packet should be created
        self.trace_enabled = True
        self.create_sync_packet(sync_t.SUPPORT, self.pipeline.inst[Pipeline.CURRENT])

    def init_settings(self, scf, ucf):
        """
        Initialise the encoder settings from
        - static configuration (hardware settings)
        - user configuration (runtime user settings)
        """
        settings = {}
        settings["resync-max"] = int(ucf["codec"]["resync-max"])
        settings["full-address"] = ucf["codec"]["full-address"] == "true"
        settings["implicit-except"] = ucf["codec"]["implicit-except"] == "true"
        settings["si-jump"] = ucf["codec"]["si-jump"] == "true"
        settings["implicit-return"] = ucf["codec"]["implicit-return"] == "true"
        settings["branch-prediction"] = ucf["codec"]["branch-prediction"] == "true"
        settings["jump-target-cache"] = ucf["codec"]["jump-target-cache"] == "true"

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

    def init_options(self):
        """
        Initialise the options (derived from the user configurations) in a form that
        will be sent in a te_inst support packet.
        Note that the order and the set of options is not dictated by the specification
        and is implementation specific.
        """
        codec = self.ucf["codec"]
        # From decoder-algorithm.h
        # define TE_OPTIONS_IMPLICIT_RETURN      (1u)
        # define TE_OPTIONS_IMPLICIT_EXCEPTION   (1u << 1)
        # define TE_OPTIONS_FULL_ADDRESS         (1u << 2)
        # define TE_OPTIONS_JUMP_TARGET_CACHE    (1u << 3)
        # define TE_OPTIONS_BRANCH_PREDICTION    (1u << 4)
        # define TE_OPTIONS_NUM_BITS             (5u)    /* number of bits to send te_options_t */

        # The order is vital here as it creates a bit string.
        options = [self.settings["implicit-return"]]
        options.append(self.settings["implicit-except"])
        options.append(self.settings["full-address"])
        options.append(self.settings["jump-target-cache"])
        options.append(self.settings["branch-prediction"])
        self.option_bits = len(options)
        return int("".join(reversed([str(int(v)) for v in options])), 2)

    def add(self, entry):
        """ Run the encoder on the CSV entry given. """
        self.i_count += 1
        self.pipeline.add(entry)
        if args.annotate:
            self.te_annotated.write("%s\n" % self.pipeline)

        if self.i_count != 1:  # Ignore the first cycle
            self.encode()

        if not self.has_sent_te_inst:
            if args.debug:
                fired = [key for key, value in self.flags.items() if value]
                debug_print("FLAGS(no packet sent)=%s" % fired)

    def update_branch_map(self, is_taken):
        """ Update the branch map data structure when a branch instruction is encountered """
        self.branches += 1
        self.branch_map.append("0" if is_taken else "1")
        debug_print("%d: branch total %d" % (self.i_count, self.branches))
        assert self.branches <= self.MAX_BRANCHES
        assert len(self.branch_map) <= self.MAX_BRANCHES

    def create_sync_packet(self, sync, icurr, thaddr=None, iexception=None):
        """ Create a synchronisation te_inst packet """

        self.te_stats["npackets"] += 1

        debug_print("%d: Create sync %s" % (self.i_count, sync.name))
        self.te_inst["format"] = format_t.SYNC.value
        self.te_inst["subformat"] = sync.value

        if sync in (sync_t.START, sync_t.TRAP):
            self.te_inst["branch"] = 0 if icurr.itype_0 == itype_t.TAKEN_BRANCH else 1
            self.te_inst["privilege"] = icurr.priv
            self.te_inst["time"] = icurr.time
            self.te_inst["context"] = icurr.context

        # Flag to record whether the trap on the current cycle is recorded
        self.trap_reported = False

        address_bits = self.settings["iaddress_width_p"] - self.settings["iaddress_lsb_p"]

        if sync == sync_t.START:
            self.te_inst["address"] = as_hex(
                self.address_handler.get_full(icurr.iaddr_0),
                address_bits
            )
            self.address_handler.set_last_address(icurr.iaddr_0)
        elif sync == sync_t.TRAP:
            assert thaddr is not None
            assert isinstance(iexception, Instruction)

            self.trap_reported = ((thaddr == 0) and
                                  (self.flags["prev_updiscon"] or self.flags["next_exception"]))

            assert iexception.itype_0 in self.exceptions
            self.te_inst["ecause"] = iexception.cause
            self.te_inst["interrupt"] = 1 if iexception.itype_0 == itype_t.INTERRUPT else 0
            self.te_inst["thaddr"] = thaddr
            self.te_inst["address"] = as_hex(
                self.address_handler.get_full(icurr.iaddr_0),
                address_bits
            )
            self.address_handler.set_last_address(icurr.iaddr_0)
            if self.te_inst["interrupt"] != 1:
                self.te_inst["tval"] = as_hex(iexception.tval, self.settings["iaddress_width_p"])

        elif sync == sync_t.CONTEXT: # pragma: no cover
            self.te_inst["privilege"] = icurr.priv
            self.te_inst["time"] = icurr.time
            self.te_inst["context"] = icurr.context
        elif sync == sync_t.SUPPORT:
            self.te_inst["ienable"] = int(self.trace_enabled)
            self.te_inst["encoder_mode"] = 0
            self.te_inst["qual_status"] = int(icurr.qualified)
            self.te_inst["ioptions"] = self.ioptions
        else: # pragma: no cover
            assert False, "Unknown sync subformat %d" % sync.value

        self.send_te_inst()
        if sync in (sync_t.START, sync_t.TRAP):
            self.resync_count = 0

    def create_branch_packet(self, inst, with_address):
        """ Create a branch or address te_inst packet """
        self.te_stats["npackets"] += 1
        self.te_inst["branches"] = self.branches
        if len(self.branch_map) == 0:
            self.te_inst["branch_map"] = 0
        else:
            self.te_inst["branch_map"] = int("".join(reversed(self.branch_map)), 2)

        if with_address:
            debug_print("%d: Create branch packet WITH address" % self.i_count)
            self.te_inst["address"] = as_hex(
                self.address_handler.get(inst.iaddr_0),
                self.settings["iaddress_width_p"] - self.settings["iaddress_lsb_p"],
            )
            if self.te_inst["branches"] != 0:
                # Address, with a branch-map
                self.te_inst["format"] = format_t.BRANCH.value
            else:
                # Address, without a branch-map
                self.te_inst["format"] = format_t.ADDR.value
                self.te_inst["branches"] = None  # Not required by this packet
                self.te_inst["branch_map"] = None  # Not required by this packet
            # Handle the setting of notify/updiscon/irreport/irdepth
            self.set_status_fields(inst, self.address_handler.get_msb(inst.iaddr_0))
            self.address_handler.set_last_address(inst.iaddr_0)
        else:
            debug_print("%d: Create branch packet WITHOUT address" % self.i_count)
            # No address
            self.te_inst["format"] = format_t.BRANCH.value
            if self.te_inst["branches"] == self.MAX_BRANCHES:
                self.te_inst["branches"] = 0
        self.send_te_inst()

    def set_status_fields(self, inst, msb):
        """ A number of status fields in te_inst packets need to be compressed before they are
        transmitted. This function takes the boolean values of these flags, together with the msb
        of the preceding address field, and encodes them in a way that improves the compression of
        the packet data. """
        # Handle the setting of notify/updiscon/irreport/irdepth to allow compression to remove
        # these in many cases
        self.te_inst["notify"] = int(self.flags["notify"]) ^ msb
        # If this bit different from notify, then this is immediately followed by a format 3 msg
        self.te_inst["updiscon"] = int(self.flags["updiscon"]) ^ self.te_inst["notify"]
        self.te_inst["irreport"] = (
            int(self.flags["irreport"]) ^ self.te_inst["updiscon"]
        )
        # When no bits required don't set the value
        if self.irdepth_bits() != 0: # pragma: no cover
            if self.te_inst["updiscon"] == self.te_inst["irreport"]:
                self.te_inst["irdepth"] = (1 << self.irdepth_bits()) - 1
            else:
                self.te_inst["irdepth"] = self.flags["irdepth"]

    def irdepth_bits(self):
        rss = self.settings["return_stack_size_p"]
        return rss + (1 if rss > 0 else 0) + self.settings["call_counter_size_p"]

    def send_te_inst(self):
        """ This function outputs the te_inst data for the current packet in the various
        formats that are required. CSV and byte stream (raw) are always produced. Annotated is
        produced if requested by the user. """

        self.has_sent_te_inst = True

        debug_print("---------------------Start of send_te_inst---------------------")
        self.branches = 0
        self.branch_map = []
        self.resync_count += 1
        # Check that no extra fields have been added as it's just a dict
        assert len(self.te_inst) == len(csv_headers.te_inst), "%s %s" % (
            self.te_inst.keys(),
            csv_headers.te_inst,
        )
        self.te_out.writerow([
            Encoder.NO_DATA if self.te_inst[key] is None else self.te_inst[key]
            for key in self.te_inst.keys()
        ])

        # Create the raw output
        self.write_raw()

        if self.te_inst["subformat"] is None:
            packet_type = "f%d" % self.te_inst["format"]
        else:
            packet_type = "f%d%d" % (self.te_inst["format"], self.te_inst["subformat"])
        assert packet_type in self.te_stats, packet_type
        self.te_stats[packet_type] += 1

        # Sanity check the "reasons" for packet generation produced by the encoder
        assert self.reasons is not None
        for reason in self.reasons:
            assert reason in self.flags

        # Debug to output flags that have fired to produce the current te_inst
        if args.debug or args.annotate:
            fired = [key for key, value in self.flags.items() if value]
            reasons = [key for key in self.reasons if self.flags[key]]
            if len(fired):
                print("FLAGS(#%d)=%s Reasons=%s" % (self.te_stats["npackets"], fired, reasons))

        if args.annotate:
            te_inst_list = []
            for key, value in self.te_inst.items():
                if value is not None:
                    if key == "format":
                        te_inst_list.append("%s=%s" % (key, format_t(value).name))
                    elif key == "subformat":
                        te_inst_list.append("%s=%s" % (key, sync_t(value).name))
                    else:
                        te_inst_list.append("%s=%s" % (key, value))
            flag_info = ", Reason[%s]" % ", ".join(reasons) if len(reasons) else ""
            # Don't include the first byte which is the payload length/msg_type
            raw_data = " Payload[%s]" % " ".join(
                ["%02x" % v for v in self.raw.byte_array[1:]]
            )
            self.te_annotated.write(
                "%s%s%s\n" % (", ".join(te_inst_list), flag_info, raw_data)
            )

        # Reset the output data
        for key in self.te_inst.keys():
            self.te_inst[key] = None

        debug_print("---------------------End of send_te_inst---------------------")

    def write_raw(self):
        """
        Write the byte stream version of the current te_inst.
        Note that this produces the compressed payload and a 1-byte header which indicates
        the length in bytes of the compressed payload.
        """

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

        # To match Sean's payload bytes numbers this needs to be added to the start
        # of the packet. BUT, if this is done then some packets (format 1) become undecodable
        # by the te_inst_reader.py as the 2 + 5 bits (format + branches fields) do not fit in
        # the 1st byte of the payload and may have been compressed away.
        # ALSO NEED TO CHANGE THE REGRESSION TO STOP check_raw() being run
        #   self.bit_array = "10" # msg_type?
        hex_fields = ("address", "tval")
        self.raw = RawWrite(self.te_out_raw, msg_type_t.TE_INST, self.te_inst, hex_fields, self.te_stats)
        self.raw.add_bits("format", 2)
        address_width = self.settings["iaddress_width_p"] - self.settings["iaddress_lsb_p"]
        if self.te_inst["format"] == format_t.SYNC:
            self.raw.add_bits("subformat", 2)
            if self.te_inst["subformat"] in (
                sync_t.START,
                sync_t.TRAP,
                sync_t.CONTEXT,
            ):
                self.raw.add_bits("branch", 1)
                self.raw.add_bits("privilege", self.settings["privilege_width_p"])
                self.raw.add_bits(
                    "time",
                    self.settings["time_width_p"]
                    if self.settings["notime_p"] == 0
                    else 0,
                )
                self.raw.add_bits(
                    "context",
                    self.settings["context_width_p"]
                    if self.settings["nocontext_p"] == 0
                    else 0,
                )
                if self.te_inst["subformat"] == sync_t.START:
                    self.raw.add_bits("address", address_width)
                elif self.te_inst["subformat"] == sync_t.TRAP:
                    self.raw.add_bits("ecause", self.settings["ecause_width_p"])
                    self.raw.add_bits("interrupt", 1)
                    self.raw.add_bits("thaddr", 1)
                    self.raw.add_bits("address", address_width)
                    self.raw.add_bits("tval", self.settings["iaddress_width_p"])
            elif self.te_inst["subformat"] == sync_t.SUPPORT:
                self.raw.add_bits("ienable", 1)
                self.raw.add_bits("encoder_mode", 1)  # Where does N come from?
                self.raw.add_bits("qual_status", 2)
                self.raw.add_bits("ioptions", self.option_bits)
                self.te_inst["denable"] = 0 # Fake value because this is instruction trace
                self.te_inst["dloss"] = 0 # Fake value because this is instruction trace
                self.te_inst["doptions"] = 0 # Fake value because this is instruction trace
                self.raw.add_bits("denable", 1)
                self.raw.add_bits("dloss", 1)
                self.raw.add_bits("doptions", 4)
            else:
                assert False, (
                    "Unknown format 3 subformat %d" % self.te_inst["subformat"]
                ) # pragma: no cover
        elif self.te_inst["format"] in (format_t.BRANCH, format_t.ADDR):
            has_address = True
            if self.te_inst["format"] == format_t.BRANCH:
                self.raw.add_bits("branches", 5)
                branch_bits, has_address = branch_map_bits(self.te_inst["branches"])
                self.raw.add_bits("branch_map", branch_bits)
            bit_end = len(self.raw)
            self.raw.add_bits("address", address_width)
            self.raw.add_bits("notify", 1)
            self.raw.add_bits("updiscon", 1)
            self.raw.add_bits("irreport", 1)
            self.raw.add_bits("irdepth", self.irdepth_bits())
            # When no address is required, check that no more bits have been added to the stream
            if not has_address:
                assert bit_end == len(self.raw)
        elif self.te_inst["format"] == format_t.EXT: # pragma: no cover
            assert False, "Format 0 not handled yet"
        else: # pragma: no cover
            assert False, "Unknown format %d" % self.te_inst["format"]

        self.raw.compress_packet()
        self.raw.output_packet()
        debug_print(
            "Raw#%d fmt:%s subfmt:%s %d bits total %d bits"
            % (
                self.te_stats["npackets"],
                self.te_inst["format"],
                self.te_inst["subformat"],
                len(self.raw),
                self.te_stats["nbits_compressed"],
            )
        )

    def init_flags(self, iprev, icurr, inext):
        """
        This function is called every time the pipeline is clocked and produces a set of flags
        that are used to determine the behaviour of the encoder at this clock cycle. The naming of
        the flags largely comes from the instruction trace algorithm given in the specification
          https://github.com/riscv-non-isa/riscv-trace-spec
        """

        # Purely for debugging the reasons list will be setup each time a packet is emitted
        self.reasons = None

        self.flags["notify"] = False

        self.flags["prev_updiscon"] = iprev.itype_0 in self.updiscons
        self.flags["curr_updiscon"] = icurr.itype_0 in self.updiscons

        self.flags["updiscon"] = self.flags["prev_updiscon"] and (
            inext.itype_0 in self.exceptions
            or (inext.priv != icurr.priv)
            or (self.resync_count == self.resync_max)
        )
        self.flags["irreport"] = False
        self.flags["irdepth"] = 0

        self.flags["prev_exception"] = iprev.itype_0 in self.exceptions

        self.flags["curr_exc_only"] = (icurr.iretire_0 == 0) and icurr.itype_0 in self.exceptions
        self.flags["curr_exception"] = icurr.itype_0 in self.exceptions

        self.flags["next_exc_only"] = (inext.iretire_0 == 0) and inext.itype_0 in self.exceptions
        self.flags["next_exception"] = inext.itype_0 in self.exceptions

        # Was the exception on the previous cycle already reported with thaddr = 0?
        self.flags["prev_reported"] = self.flags["prev_exception"] and self.trap_reported
        self.trap_reported = False

        self.flags["first_qualified"] = (not iprev.qualified and icurr.qualified)

        # Privilege change or precise context change or context change with discontinuity
        self.flags["ppccd"] = (
            (icurr.priv != iprev.priv)
            or ((icurr.context != iprev.context) and
                ((icurr.ctype == ctype_t.PRECISE_CONTEXT) or self.flags["prev_updiscon"]))
        )

        # This relates to the next instruction, unlike ppccd, which relates to the current
        # instruction.
        self.flags["ppccd_br"] = self.branches != 0 and (
            (inext.priv != icurr.priv)
            or ((inext.context != icurr.context) and
                ((inext.ctype == ctype_t.PRECISE_CONTEXT) or self.flags["curr_updiscon"]))
        )

        self.flags["er_n"] = (((icurr.iretire_0 > 0) and self.flags["curr_exception"]) or
                              self.flags["notify"])

        self.flags["cci"] = ((icurr.context != iprev.context)
                             and (icurr.ctype == ctype_t.IMPRECISE_CONTEXT))

        self.flags["resync_br"] = (self.resync_count == self.resync_max) and (
            self.branches != 0
        )

        self.flags["rpt_br"] = (self.branches == self.MAX_BRANCHES) and (
            self.pbc < self.MAX_BRANCHES
        )

        self.flags["resync_exceeded"] = self.resync_count > self.resync_max

    def encode(self):
        """
        This is the instruction trace encoder algorithm which uses the flags created in init_flags
        to determine its behaviour for this clock cycle.
        Please refer to Figure 9.1 for the flowchart which relates to this code.
        """
        iprev = self.pipeline.inst[Pipeline.PREVIOUS]
        icurr = self.pipeline.inst[Pipeline.CURRENT]
        inext = self.pipeline.inst[Pipeline.NEXT]

        self.has_sent_te_inst = False

        # Is current qualified?
        if not icurr.qualified:
            return # pragma: no cover

        # Update branch map if branch instruction
        if icurr.itype_0 in [itype_t.NONTAKEN_BRANCH, itype_t.TAKEN_BRANCH]:
            self.update_branch_map(icurr.itype_0 == itype_t.TAKEN_BRANCH)

        self.init_flags(iprev, icurr, inext)

        if self.flags["prev_exception"]:
            if self.flags["curr_exc_only"]:
                self.reasons = ["prev_exception", "curr_exc_only"]
                self.create_sync_packet(sync_t.TRAP, icurr, thaddr=0, iexception=iprev)
            else:
                if self.flags["prev_reported"]:
                    self.reasons = ["prev_exception", "prev_reported"]
                    self.create_sync_packet(sync_t.START, icurr)
                else:
                    self.reasons = ["prev_exception"]
                    self.create_sync_packet(sync_t.TRAP, icurr, thaddr=1, iexception=iprev)
            return

        # Is a sync start required? First instruction or resync required.
        if (
            self.flags["first_qualified"]
            or self.flags["ppccd"]
            or self.flags["resync_exceeded"]
        ):
            self.reasons = ["first_qualified", "ppccd", "resync_exceeded"]
            self.create_sync_packet(sync_t.START, icurr)
            return

        # Handle updiscons as defined by the settings
        if self.flags["prev_updiscon"]:
            if self.flags["curr_exc_only"]:
                self.reasons = ["prev_updiscon", "curr_exc_only"]
                self.create_sync_packet(sync_t.TRAP, icurr, thaddr=0, iexception=icurr)
            else:
                self.reasons = ["prev_updiscon"]
                self.create_branch_packet(icurr, with_address=True)
            return

        # Check if resync count has reached max and there are branches waiting to be sent
        if self.flags["resync_br"] or self.flags["er_n"]:
            self.reasons = ["resync_br", "er_n"]
            self.create_branch_packet(icurr, with_address=True)
            return

        if self.flags["next_exc_only"] or self.flags["ppccd_br"]:
            self.reasons = ["next_exc_only", "ppccd_br"]
            self.create_branch_packet(icurr, with_address=True)
            return

        if not inext.qualified: # pragma: no cover
            assert False, "Send format 0 message. Not possible with baseline Encoder"
            return

        if self.flags["rpt_br"]:
            self.reasons = ["rpt_br"]
            if self.pbc < self.MAX_BRANCHES:
                self.create_branch_packet(icurr, with_address=False)
            else: # pragma: no cover
                assert (
                    False
                ), "Send format 0 message. Branch prediction not possible in baseline"

        if self.flags["cci"]: # pragma: no cover
            self.reasons = ["cci"]
            self.create_sync_packet(sync_t.CONTEXT, None, icurr)

        # TODO Implicit return stack - maintain the call stack

    def show_state(self, msg):
        debug_print(
            ' ->>>> Encoder state:"%s" Branches:%d BranchMap:%s ResyncCount:%d'
            % (msg, self.branches, self.branch_map, self.resync_count)
        )

    def close(self):
        """
        This function is called once all of the trace data has been added to the pipeline.
        It flushes the pipeline and creates any te_inst packets that are required. It then send a
        support packet to indicate that instruction trace is disabled.
        """
        # Flush the pipeline
        self.show_state("Flushing the pipeline")
        self.pipeline.add_instruction(self.pipeline.inst[Pipeline.NEXT])
        self.encode()
        if self.reasons is None:
            self.reasons = []
        self.create_branch_packet(
            self.pipeline.inst[Pipeline.CURRENT], with_address=True
        )
        self.trace_enabled = False
        self.reasons = []
        self.create_sync_packet(
            sync_t.SUPPORT,
            self.pipeline.inst[Pipeline.NEXT],
        )
        self.show_state("Encoding complete")
        print("Read %d instructions" % self.i_count)
        print("npackets %d" % self.te_stats["npackets"])
        print("Total payload bytes %d" % (self.te_stats["nbits_compressed"] >> 3))
        print("Total uncompressed payload bytes %d" % (self.te_stats["nbits"] >> 3))
        print("Packet stats %s" % self.te_stats)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--static_cfg", help="Static Config file", type=str)
    parser.add_argument("-u", "--user_cfg", help="User Config file", type=str)
    parser.add_argument("--debug", help="Debug flag", action="store_true")
    parser.add_argument(
        "--annotate", help="Whether to produce annotated output", action="store_true"
    )
    args = parser.parse_args()
    init_debug(args.debug)

    if not args.static_cfg or not args.user_cfg: # pragma: no cover
        print("Static and User config files required")
        exit(1)
    scf = configparser.ConfigParser()
    scf.read(args.static_cfg)
    ucf = configparser.ConfigParser()
    ucf.read(args.user_cfg)

    encoder_input = "%s_input" % ucf["required"]["file-stem"]
    if not os.path.exists(encoder_input): # pragma: no cover
        print("Unable to find the input file %s" % encoder_input)
        exit(1)

    harness = EncoderHarness(scf, ucf, encoder_input)


class TestAddressHandler: # pragma: no cover
    def test_address_handler_full_addresses(self):
        address_handler = AddressHandler(32, lsb=0, use_full_address=True)
        assert address_handler.get_msb(0xFFFFFFFF) == 1
        assert address_handler.get_msb(0x7FFFFFFF) == 0
        assert address_handler.get_msb(0xFFFFFFF) == 0

    def test_address_handler_full_addresses_with_lsb(self):
        address_handler = AddressHandler(32, lsb=1, use_full_address=True)
        assert address_handler.get_msb(0xFFFFFFFF) == 1
        assert address_handler.get_msb(0x7FFFFFFF) == 0
        assert address_handler.get_msb(0xFFFFFFF) == 0

    def test_address_handler_diff_addresses(self):
        address_handler = AddressHandler(32, lsb=0, use_full_address=False)
        address_handler.set_last_address(100)
        assert address_handler.get_msb(99) == 1
        assert address_handler.get_msb(110) == 0
        assert address_handler.get_msb(0xFFFFFFF) == 0

    def test_address_handler_diff_addresses_with_lsb(self):
        address_handler = AddressHandler(32, lsb=1, use_full_address=False)
        address_handler.set_last_address(100)
        assert address_handler.get_msb(99) == 1
        assert address_handler.get_msb(110) == 0
        assert address_handler.get_msb(0xFFFFFFF) == 0
