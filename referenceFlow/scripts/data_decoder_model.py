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
# This is a python model of the data trace decoder as described in the RISCV trace
# specification found in
#   https://github.com/riscv-non-isa/riscv-trace-spec
# The references in the docstrings are to version 1.1.3-Frozen

import argparse
import csv
import os

from collections import OrderedDict
from enum import IntEnum
import configparser

from common import csv_headers
from common.data_trace import *
from common.generic import msg_type_t
from common.inst_trace import format_t, sync_t, qual_status_t
from common.raw_file import RawFile
from common.utils import *

class TeInst:
    """
    Contains the information about a single te_inst support packet read from a CSV file.
    """
    NO_DATA = '_' # Used to indicate which fields in a CSV are invalid

    def __init__(self, **fields):
        self.__dict__.update(**fields)
        for key, value in self.__dict__.items():
            if value == TeInst.NO_DATA: # pragma: no cover
                self.__dict__[key] = None
            else:
                self.__dict__[key] = int(value)
        self.format = iformat_t(self.format)
        if self.subformat is not None:
            self.subformat = sync_t(self.subformat)
        if self.qual_status is not None:
            self.qual_status = qual_status_t(self.qual_status)

    def __repr__(self): # pragma: no cover
        fields = ", ".join(
            (
                "{}={!r}".format(fieldname, getattr(self, fieldname))
                for fieldname in csv_headers.te_data_inst
                if getattr(self, fieldname) is not None
            )
        )
        return "{}({})".format(self.__class__.__name__, fields)

class TeData:
    """
    Contains the information about a single te_data packet read from a CSV file.
    """
    NO_DATA = '_' # Used to indicate which fields in a CSV are invalid

    def __init__(self, **fields):
        self.__dict__.update(**fields)
        for key, value in self.__dict__.items():
            if value == TeInst.NO_DATA: # pragma: no cover
                self.__dict__[key] = None
            elif key in ("address", "addr_msbs", "addr_lsbs", "data", "operand"):
                self.__dict__[key] = int(value, 16)
            else:
                self.__dict__[key] = int(value)
        self.format = dformat_t(self.format)

    def __repr__(self): # pragma: no cover
        fields = ", ".join(
            (
                "{}={!r}".format(fieldname, getattr(self, fieldname))
                for fieldname in csv_headers.te_data_inst
                if getattr(self, fieldname) is not None
            )
        )
        return "{}({})".format(self.__class__.__name__, fields)

class DecompressionHandler:
    """
    Holds the information about representing data or addresses.
    The compression method is decided by the support packet sent by the encoder.
    """
    def __init__(self, compression, bit_width=None):
        assert compression in compress_t.__members__.values()
        self.compression = compression
        self.bit_width = bit_width
        # For each access size record the last received value
        self.last_received = None

    def reset(self):
        self.last_received = {}

    def get(self, value, size):
        if size not in self.last_received:
            self.last_received[size] = value
            return value
        result = None
        if self.compression == compress_t.NONE:
            result = value
        elif self.compression == compress_t.XOR: # pragma: no cover
            result = value ^ self.last_received[size]
        elif self.compression == compress_t.DIFF:
            if self.bit_width is None:
                bit_width = ((1 << size) << 3)
            else:
                bit_width = self.bit_width
            result = (value + self.last_received[size]) & ((1 << bit_width) - 1)
        elif self.compression == compress_t.BEST: # pragma: no cover
            assert False, "BEST compression not supported"
        self.last_received[size] = result
        return result

class DecoderHarness:
    """ The top level class to provide a harness for the data trace decoder. """

    # RAW reading must be done one packet at a time as the options need to be set before
    # data packets can be decompressed.
    def __init__(self, scf):
        with open(traced, mode="w") as output_fd:
            output_csv = csv.writer(
                output_fd, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL
            )
            output_csv.writerow(csv_headers.spike_data)

            is_raw = (os.path.splitext(args.decoder_input)[1] == ".te_data_raw")
            mode="rb" if is_raw else "r"

            with open(args.decoder_input, mode=mode) as input_fd:
                decoder = Decoder(scf, output_csv)
                if is_raw:
                    rawfile = RawFile(input_fd)
                    while rawfile.has_data():
                        decoder.add(rawfile.process_packet(decoder.create_te))
                    debug_print("npackets %d" % rawfile.npackets)
                else: # pragma: no cover
                    reader = csv.DictReader(input_fd)
                    assert csv_headers.te_data_inst == reader.fieldnames
                    for entry in reader:
                        msg_type = int(entry['msg_type'])
                        if msg_type == msg_type_t.TE_INST:
                            decoder.add(TeInst(**entry))
                        elif msg_type == msg_type_t.TE_DATA:
                            decoder.add(TeData(**entry))
                        else:
                            assert False, "Unknown msg_type %d" % msg_type

class Decoder:
    """
    This is the main data trace decoder class which processes the te_inst/te_data packets
    in sequence and reconstructs the data trace.
    (See chapter 8 - Data Trace Encoder Output Packets, for details of the packet contents
    """

    def __init__(self, scf, output_csv):
        self.scf = scf
        self.trace_out = output_csv

        self.settings = self.init_settings(scf)
        self.diff_type = None
        self.addr_handler = None
        self.data_handler = None

        self.d_count = 0

    def init_settings(self, scf):
        """
        Initialise the decoder settings from
        - static configuration (hardware settings)
        """
        settings = {}
        # The option settings come from a support te_inst so don't set them here

        for width in ("daddress", "dblock", "data", "dsize", "dtype", "iaddr_lsbs", "lrid", "lresp", "ldata", "sdata"):
            settings["%s_width_p" % width] = int(scf["required"]["%s_width_p" % width]
            )
        return settings

    def add(self, te):
        self.d_count += 1
        if te.msg_type == msg_type_t.TE_INST:
            self.process_te_inst(te)
        elif te.msg_type == msg_type_t.TE_DATA:
            self.trace = OrderedDict({key: None for key in csv_headers.spike_data})
            self.process_te_data(te)
        else: # pragma: no cover
            assert False, "Unknown msg_type %d" % entry['msg_type']

    # Callback to be run by the raw file packet extractor
    def create_te(self, msg_type, packet_length, packet):
        def size_bits():
            return max(1, clog2(clog2((self.settings["data_width_p"] >> 3) + 1)))

        debug_print("Extract packet %d" % (self.d_count + 1))
        te = {"msg_type": msg_type}
        packet.set_output(te)
        if msg_type == msg_type_t.TE_INST:
            packet.get_bits("format", 2)
            packet.get_bits("subformat", 2)
            assert te["format"] == format_t.SYNC
            assert te["subformat"] == sync_t.SUPPORT
            packet.get_bits("ienable", 1)
            packet.get_bits("encoder_mode", 1)
            packet.get_bits("qual_status", 2)
            packet.get_bits("ioptions", 5)
            packet.get_bits("denable", 1)
            packet.get_bits("dloss", 1)
            packet.get_bits("doptions", 4)
            packet.check("Sync-Support")
            return TeInst(**te)

        assert msg_type == msg_type_t.TE_DATA
        packet.get_bits("format", 3)
        if te["format"] in (dformat_t.LOAD_ALIGNED,
                            dformat_t.LOAD_UNALIGNED,
                            dformat_t.STORE_ALIGNED,
                            dformat_t.STORE_UNALIGNED,):
            debug_print("Started reading Load/store packet")
            packet.get_bits("size", size_bits())
            if self.settings["no-data"]:
                packet.get_bits("diff", 1)
                packet.get_bits("address", self.settings["daddress_width_p"], is_hex=True)
            else:
                packet.get_bits("diff", 2)
                if self.settings["no-address"]:
                    packet.get_bits("data", self.settings["data_width_p"], is_hex=True)
                else:
                    # Note that "size" may be zero (for byte load/store) so data_len may not
                    # be present in the raw packet!
                    if te["size"] == 0:
                        te["data_len"] = 0
                    else:
                        packet.get_bits("data_len", te["size"])
                    packet.get_bits("data", (te["data_len"] + 1) << 3, is_hex=True)
                    packet.get_bits("address", self.settings["daddress_width_p"], is_hex=True)
            packet.check("Load/Store")
            return TeData(**te)

        if te["format"] == dformat_t.CSR:
            debug_print("Started reading CSR packet")
            is_32_bit = self.settings["data_width_p"] == 32
            packet.get_bits("subtype", 2)
            if self.settings["no-data"]:
                packet.get_bits("diff", 1)
                packet.get_bits("addr_msbs", 6, is_hex=True)
                packet.get_bits("addr_lsbs", 6, is_hex=True)
            else:
                packet.get_bits("diff", 2)
                packet.get_bits("data_len", 2 if is_32_bit else 3)
                packet.get_bits("data", (te["data_len"] + 1) << 3, is_hex=True)
                packet.get_bits("addr_msbs", 6, is_hex=True)
                is_read_only = ((int(te["addr_msbs"], 16) >> 4) & 0x3) == 0x3
                debug_print("CSR addr_msbs 0x%s is_read_only=%s" % (te["addr_msbs"], is_read_only))
                if is_read_only:
                    packet.get_bits("addr_lsbs", 6, is_hex=True)
                else:
                    packet.get_bits("op_len", 2 if is_32_bit else 3)
                    packet.get_bits("operand", (te["op_len"] + 1) << 3, is_hex=True)
                    packet.get_bits("addr_lsbs", 6, is_hex=True)
            packet.check("CSR")
            return TeData(**te)

        if te["format"] == dformat_t.ATOMIC:
            debug_print("Started reading Atomic packet")
            packet.get_bits("subtype", 3)
            packet.get_bits("size", size_bits())
            if self.settings["no-data"]:
                packet.get_bits("diff", 1)
                packet.get_bits("address", self.settings["daddress_width_p"], is_hex=True)
            else:
                packet.get_bits("diff", 2)
                if self.settings["no-address"]:
                    packet.get_bits("op_len", te["size"])
                    packet.get_bits("operand", (te["op_len"] + 1) << 3, is_hex=True)
                    packet.get_bits("data", self.settings["data_width_p"], is_hex=True)
                else:
                    packet.get_bits("op_len", te["size"])
                    packet.get_bits("operand", (te["op_len"] + 1) << 3, is_hex=True)
                    packet.get_bits("data_len", te["size"])
                    packet.get_bits("data", (te["data_len"] + 1) << 3, is_hex=True)
                    packet.get_bits("address", self.settings["daddress_width_p"], is_hex=True)
            packet.check("ATOMIC")
            return TeData(**te)

        assert False, "Unknown format type %s" % te["format"] # pragma: no cover
        return None # pragma: no cover

    def process_te_inst(self, te_inst):
        """
        Derive the options from a te_inst support packet.
        Note that the order and the set of options is not dictated by the specification
        and is implementation specific.
        """

        assert te_inst.format == iformat_t.SYNC
        assert te_inst.subformat == sync_t.SUPPORT
        options = te_inst.doptions
        self.settings["no-address"] = (options & 1) == 1
        self.settings["no-data"] = (options >> 1) & 1 == 1
        self.settings["full-daddress"] = (options >> 2) & 1 == 1
        self.settings["full-data"] = (options >> 3) & 1 == 1

        debug_print("no-address:%s" % self.settings["no-address"])
        debug_print("no-data:%s" % self.settings["no-data"])
        debug_print("full-daddress:%s" % self.settings["full-daddress"])
        debug_print("full-data:%s" % self.settings["full-data"])

        if self.settings["no-address"]:
            # Data only
            self.diff_type = diff_data_t.FULL if self.settings["full-data"] else diff_data_t.COMPRESSED
        elif self.settings["no-data"]:
            # Address only
            self.diff_type = diff_addr_t.FULL if self.settings["full-daddress"] else diff_addr_t.DIFF
        else:
            # Address and data
            if self.settings["full-daddress"]:
                if self.settings["full-data"]:
                    self.diff_type = diff_t.FULL_ADDR_DATA
                else: # pragma: no cover
                    assert False, "Full data addresses and compressed data not allowed"
            else:
                if self.settings["full-data"]:
                    self.diff_type = diff_t.DIFF_ADDR_FULL_DATA
                else:
                    self.diff_type = diff_t.DIFF_ADDR_XOR_DATA

        addr_compression = compress_t.NONE if self.settings["full-daddress"] else compress_t.DIFF
        self.addr_handler = DecompressionHandler(addr_compression, self.settings["daddress_width_p"])
        data_compression = compress_t.NONE if self.settings["full-data"] else compress_t.DIFF
        self.data_handler = DecompressionHandler(data_compression)

        self.addr_handler.reset()
        self.data_handler.reset()

    def process_te_data(self, te_data):
        self.trace["DRETIRE"] = 1
        if te_data.format in (dformat_t.LOAD_ALIGNED,
                              dformat_t.LOAD_UNALIGNED,
                              dformat_t.STORE_ALIGNED,
                              dformat_t.STORE_UNALIGNED):
            self.process_load_store(te_data)
        elif te_data.format == dformat_t.CSR:
            self.process_csr(te_data)
        elif te_data.format == dformat_t.ATOMIC:
            self.process_atomic(te_data)
        else: # pragma: no cover
            assert False, "Data format %s not supported" % te_data.format
        self.send_trace()

    def process_load_store(self, te_data):
        self.trace["DTYPE"] = dtype_t.LOAD.value if te_data.format in (dformat_t.LOAD_ALIGNED, dformat_t.LOAD_UNALIGNED) else dtype_t.STORE.value
        self.trace["DSIZE"] = te_data.size
        is_aligned = te_data.format in (dformat_t.LOAD_ALIGNED, dformat_t.STORE_ALIGNED)
        if self.settings["no-address"]:
            self.trace["DADDR"] = 0
            data_width = self.settings["data_width_p"]
        else:
            address = self.addr_handler.get(te_data.address, te_data.size)
            address = address << te_data.size if is_aligned else address
            self.trace["DADDR"] = as_hex(address, self.settings["daddress_width_p"])
            if not self.settings["no-data"]:
                data_width = (te_data.data_len + 1) << 3
        if self.settings["no-data"]:
            self.trace["DATA"] = 0
        else:
            self.trace["DATA"] = as_hex(self.data_handler.get(te_data.data, te_data.size), data_width)

    def process_csr(self, te_data):
        if te_data.subtype == csr_t.RW:
            self.trace["DTYPE"] = dtype_t.CSR_READ_WRITE.value
        elif te_data.subtype == csr_t.RS:
            self.trace["DTYPE"] = dtype_t.CSR_READ_SET.value
        elif te_data.subtype == csr_t.RC:
            self.trace["DTYPE"] = dtype_t.CSR_READ_CLEAR.value
        else: # pragma: no cover
            assert False, "Unknown subtype %s" % te_data.subtype

        assert self.settings["data_width_p"] in (32, 64)
        size = 3 if self.settings["data_width_p"] == 64 else 2
        # Since there are two pieces of data the width is doubled, bit width is 2**DSIZE
        self.trace["DSIZE"] = size + 1
        csr = (te_data.addr_msbs << 6) | te_data.addr_lsbs
        self.trace["DADDR"] = as_hex(csr, self.settings["daddress_width_p"])

        if self.settings["no-data"]:
            self.trace["DATA"] = 0
        else:
            # Decompressing the operand and data is done in the order listed in the packet format
            data_width = (te_data.data_len + 1) << 3
            data = self.data_handler.get(te_data.data, size)
            operand = 0
            operand_width = data_width

            # Bits 11:10 == 0x3 mark a CSR as read-only
            is_read_only = ((csr >> 10) & 0x3) == 0x3
            if not is_read_only:
                operand_width = (te_data.op_len + 1) << 3
                operand = self.data_handler.get(te_data.operand, size)
            self.trace["DATA"] = as_hex(operand << data_width | data, data_width + operand_width)

    def process_atomic(self, te_data):
        if te_data.subtype == atomic_t.SWAP:
            self.trace["DTYPE"] = dtype_t.ATOMIC_SWAP.value
        elif te_data.subtype == atomic_t.ADD:
            self.trace["DTYPE"] = dtype_t.ATOMIC_ADD.value
        elif te_data.subtype == atomic_t.AND:
            self.trace["DTYPE"] = dtype_t.ATOMIC_AND.value
        elif te_data.subtype == atomic_t.OR:
            self.trace["DTYPE"] = dtype_t.ATOMIC_OR.value
        elif te_data.subtype == atomic_t.XOR:
            self.trace["DTYPE"] = dtype_t.ATOMIC_XOR.value
        elif te_data.subtype == atomic_t.MAX:
            self.trace["DTYPE"] = dtype_t.ATOMIC_MAX.value
        elif te_data.subtype == atomic_t.MIN:
            self.trace["DTYPE"] = dtype_t.ATOMIC_MIN.value
        else: # pragma: no cover
            assert False, "Unknown subtype %s" % te_data.subtype

        # Since there are two pieces of data the width is doubled, bit width is 2**DSIZE
        self.trace["DSIZE"] = te_data.size + 1

        if self.settings["no-address"]:
            self.trace["DADDR"] = 0
            data_width = self.settings["data_width_p"]
        else:
            # Address is always aligned
            address = self.addr_handler.get(te_data.address, te_data.size) << te_data.size
            self.trace["DADDR"] = as_hex(address, self.settings["daddress_width_p"])
            if not self.settings["no-data"]:
                data_width = (te_data.data_len + 1) << 3

        if self.settings["no-data"]:
            self.trace["DATA"] = 0
        else:
            # Decompressing the operand and data is done in the order listed in the packet format
            operand_width = (te_data.op_len + 1) << 3
            operand = self.data_handler.get(te_data.operand, te_data.size)
            data = self.data_handler.get(te_data.data, te_data.size)
            self.trace["DATA"] = as_hex(operand << data_width | data, data_width + operand_width)

    def send_trace(self):
        self.trace_out.writerow(self.trace.values())

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--static_cfg", help="Static Config file", type=str)
    parser.add_argument("--debug", help="Debug flag", action="store_true")
    parser.add_argument("-i", "--decoder-input", help="Input te_inst file", type=str)
    args = parser.parse_args()
    init_debug(args.debug)

    if not args.static_cfg: # pragma: no cover
        print("Static config file required")
        exit(1)
    scf = configparser.ConfigParser()
    scf.read(args.static_cfg)

    if not args.decoder_input: # pragma: no cover
        print("Input te file required")
        exit(1)

    if not os.path.exists(args.decoder_input): # pragma: no cover
        print("Unable to find the input file %s" % args.decoder_input)
        exit(1)

    traced = (
        os.path.splitext(os.path.basename(args.decoder_input))[0] + ".decoder.trace"
    )

    harness = DecoderHarness(scf)
