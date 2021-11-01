#!/usr/bin/env python3

###########################################################################################
#
# SPDX-License-Identifier: BSD-2-Clause
# SPDX-FileCopyrightText: Copyright 2019-2021 Siemens. All rights reserved.
#
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

# Utility to compare a spike data trace input file and the generated data trace file
# produced by the decoder.
# Exits with status 0 if they are identical otherwise exit code is the number of
# lines which differ.
import argparse
import csv
import os
import configparser

from common.utils import *
from common.data_trace import *

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

    def value(self, key):
        if key in ("daddr", "data"):
            return "%lx" % getattr(self, key)
        return getattr(self, key)

    def __repr__(self):
        fields = ", ".join(
            (
                "{}={!r}".format(fieldname, self.value(fieldname))
                for fieldname in IN_HEADER
            )
        )
        return "{}({})".format(self.__class__.__name__, fields)

parser = argparse.ArgumentParser()
parser.add_argument("spike_trace",
                    help="Source spike data trace file")
parser.add_argument("decoded_trace",
                    help="Decoded data trace file")
parser.add_argument("user_cfg",
                    help="User config file")
parser.add_argument("--limit",
                    help="Limit number of differences reported")

args = parser.parse_args()
if not os.path.exists(args.spike_trace):
    print("Unable to find the spike trace file %s" % args.spike_trace)
    exit(1)
if not os.path.exists(args.decoded_trace):
    print("Unable to find the decoded trace file %s" % args.decoded_trace)
    exit(1)

ucf = configparser.ConfigParser()
ucf.read(args.user_cfg)

has_address = ucf["codec"]["no-address"] == "false"
has_data = ucf["codec"]["no-data"] == "false"

# Only report the first n differences
difference_limit = 20
if args.limit:
    difference_limit = int(args.limit)

IN_HEADER = None
with open(args.spike_trace) as spike_fd:
    reader = DictReaderInsensitive(spike_fd)
    IN_HEADER = reader.fieldnames
    spike_data_list = [TraceData(**entry) for entry in reader]

with open(args.decoded_trace) as decoded_fd:
    reader = DictReaderInsensitive(decoded_fd)
    assert IN_HEADER == reader.fieldnames
    decoded_data_list = [TraceData(**entry) for entry in reader]

differences = 0
line = 1
if has_address and has_data:
    for spike, decoded in zip(spike_data_list, decoded_data_list):
        if ((spike.dtype != decoded.dtype) or
            (spike.daddr != decoded.daddr) or
            (spike.dsize != decoded.dsize) or
            (spike.data != decoded.data)):
            if differences <= difference_limit:
                print("Difference\n   spike=%s\n decoded=%s\n    line=%d" % (spike, decoded, line))
                differences += 1
            line += 1
elif has_address:
    for spike, decoded in zip(spike_data_list, decoded_data_list):
        if ((spike.dtype != decoded.dtype) or
            (spike.daddr != decoded.daddr) or
            (spike.dsize != decoded.dsize)):
            if differences <= difference_limit:
                print("Difference\n   spike=%s\n decoded=%s\n    line=%d" % (spike, decoded, line))
                differences += 1
            line += 1
elif has_data:
    for spike, decoded in zip(spike_data_list, decoded_data_list):
        if ((spike.dtype != decoded.dtype) or
            (spike.dsize != decoded.dsize) or
            (spike.data != decoded.data)):
            if differences <= difference_limit:
                print("Difference\n   spike=%s\n decoded=%s\n    line=%d" % (spike, decoded, line))
                differences += 1
            line += 1
else:
    print("No address and no data is not permitted")
    exit(1)

length_difference = len(spike_data_list) - len(decoded_data_list)
if length_difference == 0:
    print("Traces have the same length")
else:
    if length_difference > 0:
        print("Error Spike has %d lines more than Decoded (%d)" % (length_difference, len(decoded_data_list)))
    else:
        print("Error Decoded has %d lines more than Spike (%d)" % (-length_difference, len(spike_data_list)))

if differences == 0 and length_difference == 0:
    print("Traces are identical")
else:
    print("%d content differences found" % differences)

exit(differences + abs(length_difference))
