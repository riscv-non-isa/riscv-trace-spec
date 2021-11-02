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
# This is a python model of the data trace encoder as described in the RISCV trace
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
from common.raw_write import RawWrite
from common.utils import *

class TraceData:
    """
    Contains the information about a single data trace (from spike) read from a CSV file
    """
    def __init__(self, **fields):
        self.__dict__.update(**fields)
        for key, value in self.__dict__.items():
            if key in ("daddr", "data"):
                self.__dict__[key] = int(value, 16)
            else:
                self.__dict__[key] = int(value)
        self.dtype = dtype_t(self.dtype)

    def __repr__(self):
        fields = ", ".join(
            (
                "{}={!r}".format(fieldname, getattr(self, fieldname))
                for fieldname in csv_headers.spike_data_lower
            )
        )
        return "{}({})".format(self.__class__.__name__, fields)

class CompressionHandler:
    """
    Holds the information about representing data or addresses.
    The compression method is decided by the user configuration.
    """
    def __init__(self, compression):
        assert compression in compress_t.__members__.values()
        self.compression = compression
        # For each access size record the last sent value
        self.last_sent = None

    def reset(self):
        self.last_sent = {}

    def get(self, value, size):
        if size not in self.last_sent:
            self.last_sent[size] = value
            return value
        result = None
        if self.compression == compress_t.NONE:
            result = value
        elif self.compression == compress_t.XOR: # pragma: no cover
            result = value ^ self.last_sent[size]
        elif self.compression == compress_t.DIFF:
            result = value - self.last_sent[size]
        elif self.compression == compress_t.BEST: # pragma: no cover
            assert False, "BEST compression not supported"
        self.last_sent[size] = value
        return result

class EncoderHarness:
    """ The top level class to provide a harness for the data trace encoder. """

    def __init__(self, scf, ucf, encoder_input):
        # Only handle the unified case
        te_data = os.path.splitext(os.path.basename(encoder_input))[0] + ".te_data"
        te_data_raw = te_data + "_raw"

        with open(te_data, mode="w") as output_fd, open(te_data_raw, mode="w+b") as raw_fd:
            output_csv = csv.writer(
                output_fd, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL
            )
            output_csv.writerow(csv_headers.te_data_inst)

            with open(encoder_input) as input_fd:
                reader = DictReaderInsensitive(input_fd)
                assert csv_headers.spike_data_lower == reader.fieldnames
                trace_data_list = [TraceData(**entry) for entry in reader]
                encoder = Encoder(scf, ucf, output_csv, raw_fd, trace_data_list)

class Encoder:
    """
    This is the main data trace encoder class which processes the dtype information from the core and
    generates te_inst/te_data packets.
    """
    NO_DATA = '_' # Used to indicate which fields in a CSV are invalid

    def __init__(self, scf, ucf, output_csv, te_out_raw, trace_data_list):
        self.scf = scf
        self.ucf = ucf
        self.te_out = output_csv
        self.te_out_raw = te_out_raw
        self.trace_data_list = trace_data_list

        self.settings = self.init_settings(scf, ucf)
        self.option_bits = None
        self.doptions = self.init_options()
        self.te_stats = {}
        self.te_stats["npackets"] = 0
        self.te_stats["nbits_compressed"] = 0
        self.te_stats["nbits"] = 0

        self.diff_type = None
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

        self.d_count = 0
        self.te = OrderedDict({key: None for key in csv_headers.te_data_inst})

        addr_compression = compress_t.NONE if self.settings["full-daddress"] else compress_t.DIFF
        self.addr_handler = CompressionHandler(addr_compression)
        data_compression = compress_t.NONE if self.settings["full-data"] else compress_t.DIFF
        self.data_handler = CompressionHandler(data_compression)

        # Before doing anything a support packet should be created
        self.create_support_packet()

        for trace_data in self.trace_data_list:
            if args.debug:
                debug_print(trace_data)
            self.encode(trace_data)

    def init_settings(self, scf, ucf):
        """
        Initialise the encoder settings from
        - static configuration (hardware settings)
        - user configuration (runtime user settings)
        """
        settings = {}
        settings["full-daddress"] = ucf["codec"]["full-daddress"] == "true"
        settings["full-data"] = ucf["codec"]["full-data"] == "true"
        settings["no-address"] = ucf["codec"]["no-address"] == "true"
        settings["no-data"] = ucf["codec"]["no-data"] == "true"
        settings["data-compress"] = int(ucf["codec"]["data-compress"])
        assert not (settings["no-address"] and settings["no-data"])

        debug_print("no-address:%s" % settings["no-address"])
        debug_print("no-data:%s" % settings["no-data"])
        debug_print("full-daddress:%s" % settings["full-daddress"])
        debug_print("full-data:%s" % settings["full-data"])

        for width in ("daddress", "dblock", "data", "dsize", "dtype", "iaddr_lsbs", "lrid", "lresp", "ldata", "sdata"):
            settings["%s_width_p" % width] = int(scf["required"]["%s_width_p" % width]
            )
        return settings

    def init_options(self):
        """
        Initialise the options (derived from the user configurations) in a form that
        will be sent in a te_inst support packet.
        Note that the order and the set of options is not dictated by the specification
        and is implementation specific.
        """
        codec = self.ucf["codec"]
        # The order is vital here as it creates a bit string.
        options = [self.settings["no-address"]]
        options.append(self.settings["no-data"])
        options.append(self.settings["full-daddress"])
        options.append(self.settings["full-data"])
        self.option_bits = len(options)
        return int("".join(reversed([str(int(v)) for v in options])), 2)

    def create_support_packet(self, denabled=1):
        self.te["msg_type"] = msg_type_t.TE_INST.value
        self.te["format"] = iformat_t.SYNC.value
        self.te["subformat"] = sync_t.SUPPORT.value
        self.te["denable"] = denabled
        self.te["encoder_mode"] = 0
        self.te["qual_status"] = qual_status_t.NO_CHANGE.value
        self.te["doptions"] = self.doptions

        self.send_te()

        self.addr_handler.reset()
        self.data_handler.reset()

    def send_te(self):
        """ This function outputs the te_inst/te_data for the current packet in the various
        formats that are required. CSV and byte stream (raw) are always produced. Annotated is
        produced if requested by the user. """
        self.d_count += 1
        debug_print("---------------------Start of send_te %d--------------------" % self.d_count)
        # Check that no extra fields have been added as it's just a dict
        assert len(self.te) == len(csv_headers.te_data_inst), "%s %s" % (
            self.te.keys(),
            csv_headers.te_data_inst,
        )
        self.te_out.writerow([
            Encoder.NO_DATA if self.te[key] is None else self.te[key]
            for key in self.te.keys()
        ])

        # Create the raw output
        self.write_raw()

        # Reset the output data
        for key in self.te.keys():
            self.te[key] = None

        debug_print("---------------------End of send_te %d---------------------" % self.d_count)

    def write_raw(self):
        """
        Write the byte stream version of the current te_inst/te_data.
        Note that this produces the compressed payload and a 1-byte header which indicates
        the length in bytes of the compressed payload and contains the msg_type.
        """
        def size_bits():
            return max(1, clog2(clog2((self.settings["data_width_p"] >> 3) + 1)))

        if self.te["msg_type"] == msg_type_t.TE_INST:
            hex_fields = ()
            raw = RawWrite(self.te_out_raw, self.te["msg_type"], self.te, hex_fields, self.te_stats)
            raw.add_bits("format", 2)
            raw.add_bits("subformat", 2)
            self.te["ienable"] = 0 # Fake value because this is data trace
            raw.add_bits("ienable", 1)
            raw.add_bits("encoder_mode", 1)
            raw.add_bits("qual_status", 2)
            self.te["ioptions"] = 0 # Fake value because this is data trace
            raw.add_bits("ioptions", 5)
            raw.add_bits("denable", 1)
            self.te["dloss"] = 0
            raw.add_bits("dloss", 1)
            raw.add_bits("doptions", self.option_bits)
        else:
            hex_fields = ("address", "addr_msbs", "addr_lsbs", "data", "operand")
            raw = RawWrite(self.te_out_raw, self.te["msg_type"], self.te, hex_fields, self.te_stats)
            raw.add_bits("format", 3)
            if self.te["format"] in (dformat_t.LOAD_ALIGNED,
                                     dformat_t.LOAD_UNALIGNED,
                                     dformat_t.STORE_ALIGNED, dformat_t.STORE_UNALIGNED):
                assert size_bits() != 0
                raw.add_bits("size", size_bits())
                if self.settings["no-data"]:
                    raw.add_bits("diff", 1)
                else:
                    raw.add_bits("diff", 2)
                    # Note that "size" may be zero (for byte load/store) so data_len may not
                    # be present in the raw packet!
                    if self.te["size"] == 0:
                        assert self.te["data_len"] in (0, None), self.te["data_len"]
                    raw.add_bits("data_len", self.te["size"])
                    if self.settings["no-address"]:
                        raw.add_bits("data", self.settings["data_width_p"])
                    else:
                        raw.add_bits("data", (self.te["data_len"] + 1) << 3)
                raw.add_bits("address", self.settings["daddress_width_p"])
            elif self.te["format"] == dformat_t.CSR:
                raw.add_bits("subtype", 2)
                if self.settings["no-data"]:
                    raw.add_bits("diff", 1)
                else:
                    raw.add_bits("diff", 2)
                    len_bits = 3 if self.settings["data_width_p"] == 64 else 2
                    raw.add_bits("data_len", len_bits)
                    raw.add_bits("data", (self.te["data_len"] + 1) << 3)
                raw.add_bits("addr_msbs", 6)
                if not self.settings["no-data"]:
                    # If addr[11:10] == 0x3
                    is_read_only = ((int(self.te["addr_msbs"], 16) >> 4) & 0x3) == 0x3
                    if not is_read_only:
                        raw.add_bits("op_len", len_bits)
                        raw.add_bits("operand", (self.te["op_len"] + 1) << 3)
                raw.add_bits("addr_lsbs", 6)
            elif self.te["format"] == dformat_t.ATOMIC:
                raw.add_bits("subtype", 3)
                raw.add_bits("size", size_bits())
                if self.settings["no-data"]:
                    raw.add_bits("diff", 1)
                else:
                    raw.add_bits("diff", 2)
                    raw.add_bits("op_len", self.te["size"])
                    raw.add_bits("operand", (self.te["op_len"] + 1) << 3)
                    if self.settings["no-address"]:
                        raw.add_bits("data", self.settings["data_width_p"])
                    else:
                        raw.add_bits("data_len", self.te["size"])
                        raw.add_bits("data", (self.te["data_len"] + 1) << 3)
                raw.add_bits("address", self.settings["daddress_width_p"])
            else: # pragma: no cover
                assert False, "Unknown format type %s" % self.te["format"]

        raw.compress_packet()
        raw.output_packet()

    def encode(self, trace_data):
        """
        This is the data trace encoder algorithm
        """
        if trace_data.dretire == 0: # pragma: no cover
            return

        self.te["msg_type"] = msg_type_t.TE_DATA.value
        self.te['diff'] = self.diff_type.value
        if trace_data.dtype in (dtype_t.LOAD, dtype_t.STORE):
            self.encode_load_store(trace_data, trace_data.dtype == dtype_t.LOAD)
        elif trace_data.dtype in (dtype_t.CSR_READ_WRITE,
                                  dtype_t.CSR_READ_SET,
                                  dtype_t.CSR_READ_CLEAR):
            self.encode_csr(trace_data)
        elif trace_data.dtype in (dtype_t.ATOMIC_SWAP,
                                  dtype_t.ATOMIC_ADD,
                                  dtype_t.ATOMIC_AND,
                                  dtype_t.ATOMIC_OR,
                                  dtype_t.ATOMIC_XOR,
                                  dtype_t.ATOMIC_MAX,
                                  dtype_t.ATOMIC_MIN,):
            self.encode_atomic(trace_data)
        elif trace_data.dtype == dtype_t.STORE_FAILURE: # pragma: no cover
            pass
        else: # pragma: no cover
            assert(False), "Error: Unknown dtype %d" % trace_data.dtype.value

        assert self.te['format'] is not None
        self.send_te()

    def addr_info(self, addr, size):
        mask = (1 << size) - 1
        is_aligned = ((addr & mask) == 0)
        address = addr >> size if is_aligned else addr
        return (is_aligned, address)

    def encode_load_store(self, trace_data, is_load):
        size = trace_data.dsize
        self.te['size'] = size
        (is_aligned, address) = self.addr_info(trace_data.daddr, size)
        if is_load:
            self.te['format'] = dformat_t.LOAD_ALIGNED.value if is_aligned else dformat_t.LOAD_UNALIGNED.value
        else:
            self.te['format'] = dformat_t.STORE_ALIGNED.value if is_aligned else dformat_t.STORE_UNALIGNED.value
        if self.settings["no-address"]:
            data_width = self.settings["data_width_p"]
        else:
            self.te["address"] = as_hex(self.addr_handler.get(address, size), self.settings["daddress_width_p"])
            if not self.settings["no-data"]:
                self.te['data_len'] = (1 << self.te['size']) - 1
                data_width = (self.te['data_len'] + 1) << 3
        if not self.settings["no-data"]:
            self.te["data"] = as_hex(self.data_handler.get(trace_data.data, size), data_width)

    # Atomic and CSR accesses have either both load and store data, or store data and an operand.
    # For CSRs and unified atomics, both values are reported via data, with the store data in the
    # LSBs and the load data or operand in the MSBs.
    def get_operand_data(self, data, data_bytes):
        bit_width = data_bytes << 3
        mask = (1 << bit_width) - 1
        return (data >> bit_width) & mask

    def get_store_data(self, data, data_bytes):
        bit_width = data_bytes << 3
        mask = (1 << bit_width) - 1
        return data & mask

    def encode_csr(self, trace_data):
        self.te["format"] = dformat_t.CSR.value
        if trace_data.dtype == dtype_t.CSR_READ_WRITE:
            self.te["subtype"] = csr_t.RW.value
        elif trace_data.dtype == dtype_t.CSR_READ_SET:
            self.te["subtype"] = csr_t.RS.value
        elif trace_data.dtype == dtype_t.CSR_READ_CLEAR:
            self.te["subtype"] = csr_t.RC.value

        self.te['addr_msbs'] = as_hex((trace_data.daddr >> 6) & 0x3f, 6)
        self.te['addr_lsbs'] = as_hex(trace_data.daddr & 0x3f, 6)
        assert (int(self.te['addr_msbs'], 16) << 6) + int(self.te['addr_lsbs'], 16) == trace_data.daddr

        if not self.settings["no-data"]:
            # CSRs record two values and therefore the "size" of each element is half this
            size = trace_data.dsize - 1

            # Compressing the operand and data is done in the order listed in the packet format
            self.te['data_len'] = (1 << size) - 1
            data_width = (self.te['data_len'] + 1) << 3
            store_data = self.get_store_data(trace_data.data, self.te['data_len'] + 1)
            self.te["data"] = as_hex(self.data_handler.get(store_data, size), data_width)

            # If addr[11:10] == 0x3
            is_read_only = ((trace_data.daddr >> 10) & 0x3) == 0x3
            debug_print("CSR 0x%lx is_read_only=%s" % (trace_data.daddr, is_read_only))
            if not is_read_only:
                self.te['op_len'] = (1 << size) - 1
                op_width = (self.te['op_len'] + 1) << 3
                operand_data = self.get_operand_data(trace_data.data, self.te['op_len'] + 1)
                self.te["operand"] = as_hex(self.data_handler.get(operand_data, size), op_width)

    def encode_atomic(self, trace_data):
        # Atomic record two values and therefore the "size" of each element is half this
        size = trace_data.dsize - 1
        self.te['size'] = size
        (is_aligned, address) = self.addr_info(trace_data.daddr, size)
        assert is_aligned, "Atomic instruction address is not aligned %lx %d" % (trace_data.daddr, size)

        self.te["format"] = dformat_t.ATOMIC.value
        if trace_data.dtype == dtype_t.ATOMIC_SWAP:
            self.te["subtype"] = atomic_t.SWAP.value
        elif trace_data.dtype == dtype_t.ATOMIC_ADD:
            self.te["subtype"] = atomic_t.ADD.value
        elif trace_data.dtype == dtype_t.ATOMIC_AND:
            self.te["subtype"] = atomic_t.AND.value
        elif trace_data.dtype == dtype_t.ATOMIC_OR:
            self.te["subtype"] = atomic_t.OR.value
        elif trace_data.dtype == dtype_t.ATOMIC_XOR:
            self.te["subtype"] = atomic_t.XOR.value
        elif trace_data.dtype == dtype_t.ATOMIC_MAX:
            self.te["subtype"] = atomic_t.MAX.value
        elif trace_data.dtype == dtype_t.ATOMIC_MIN:
            self.te["subtype"] = atomic_t.MIN.value

        if not self.settings["no-address"]:
            self.te["address"] = as_hex(self.addr_handler.get(address, size), self.settings["daddress_width_p"])

        if not self.settings["no-data"]:
            if self.settings["no-address"]:
                data_width = self.settings["data_width_p"]
            else:
                self.te['data_len'] = (1 << size) - 1
                data_width = (self.te['data_len'] + 1) << 3

            # Compressing the operand and data is done in the order listed in the packet format
            self.te['op_len'] = (1 << size) - 1
            op_width = (self.te['op_len'] + 1) << 3
            operand_data = self.get_operand_data(trace_data.data, self.te['op_len'] + 1)
            self.te["operand"] = as_hex(self.data_handler.get(operand_data, size), op_width)
            store_data = self.get_store_data(trace_data.data, data_width >> 3)
            self.te["data"] = as_hex(self.data_handler.get(store_data, size), data_width)


    def close(self):
        """
        It sends a support packet to indicate that data trace is disabled.
        """
        self.create_support_packet(denabled=False)
        print("Read %d data traces" % self.d_count)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--static_cfg", help="Static Config file", type=str)
    parser.add_argument("-u", "--user_cfg", help="User Config file", type=str)
    parser.add_argument("--debug", help="Debug flag", action="store_true")
    args = parser.parse_args()
    init_debug(args.debug)

    if not args.static_cfg or not args.user_cfg: # pragma: no cover
        print("Static and User config files required")
        exit(1)
    scf = configparser.ConfigParser()
    scf.read(args.static_cfg)
    ucf = configparser.ConfigParser()
    ucf.read(args.user_cfg)

    spike_dir = "%s/../spike" % os.path.dirname(ucf["required"]["file-stem"])
    test_name = os.path.splitext(os.path.basename(ucf["required"]["file-stem"]))[0]
    encoder_input = "%s/%s.spike_data_trace" % (spike_dir, test_name)
    if not os.path.exists(encoder_input): # pragma: no cover
        print("Unable to find the input file %s" % encoder_input)
        exit(1)

    harness = EncoderHarness(scf, ucf, encoder_input)


class TestClog2: # pragma: no cover
    def test_clog2(self):
        assert clog2(15) == 4
        assert clog2(16) == 4
        assert clog2(17) == 5

    def test_clog2_to_size(self):
        widths = [16, 32, 64, 128]
        sizes = []
        for data_width_p in widths:
            sizes.append(clog2(clog2((data_width_p >> 3) + 1)))
        print(sizes)
        assert sizes[0] == 1
        assert sizes[1] == 2
        assert sizes[2] == 2
        assert sizes[3] == 3
