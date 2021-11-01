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

# Utility to compare a spike trace input file and the generated pc transition file
# produced by the decoder.
# Has to remove cycles which threw an exception before doing the comparison.
# Exits with status 0 if they are identical otherwise exit code is the number of
# lines which differ.
import argparse
import csv
import os

from common import csv_headers

def check_spike_trace_header(header):
    expected_length = 8
    if len(header) != expected_length:
        print("Error reading header expected %d entries got %d" % (expected_length, len(header)))
        exit(1)
    header_str = ','.join(header)
    if header_str != ','.join(csv_headers.spike_inst):
        print("Error reading header %s" % header_str)
        exit(1)

ecall = '73' # Hex value
ebreak = '100073' # Hex value

def discard_exception(entry):
    is_exception = entry[4] == '1'
    if is_exception:
        opcode = entry[2]
        if opcode not in (ecall, ebreak):
            return True

    return False

parser = argparse.ArgumentParser()
parser.add_argument("spike_trace",
                    help="Source spike trace file")
parser.add_argument("decoded_trace",
                    help="Decoded trace file")
parser.add_argument("--limit",
                    help="Limit number of differences reported")

args = parser.parse_args()
if not os.path.exists(args.spike_trace):
    print("Unable to find the spike trace file %s" % args.spike_trace)
    exit(1)
if not os.path.exists(args.decoded_trace):
    print("Unable to find the decoded trace file %s" % args.decoded_trace)
    exit(1)

# Only report the first n differences
difference_limit = 20
if args.limit:
    difference_limit = int(args.limit)

spike_pcs = []
decoded_pcs = []
discarded_pcs = []
with open(args.spike_trace) as spike_fd:
    reader = csv.reader(spike_fd)
    is_header = True
    for entry in reader:
        if is_header:
            is_header = False
            check_spike_trace_header(entry)
            continue
        if discard_exception(entry):
            print("Discarded exception at pc 0x%s" % entry[1])
            discarded_pcs.append(entry[1])
        else:
            spike_pcs.append(entry[1])

# Write a filtered version of the spike trace so that a diff can be done for debugging
spike_filtered = "%s_filtered" % args.spike_trace
with open(spike_filtered, "w") as filtered_fd:
    for pc in spike_pcs:
        filtered_fd.write("%s\n" % pc)

with open(args.decoded_trace) as decoded_fd:
    for line in decoded_fd:
        entry = line.split()
        decoded_pcs.append(entry[0])

differences = 0
line = 1
for spike, decoded in zip(spike_pcs, decoded_pcs):
    if spike != decoded:
        if differences <= difference_limit:
            print("Difference spike=%s decoded=%s line:%d" % (spike, decoded, line))
        differences += 1
    line += 1

length_difference = len(spike_pcs) - len(decoded_pcs)
if length_difference == 0:
    print("Traces have the same length")
else:
    if length_difference > 0:
        print("Error Spike has %d lines more than Decoded (%d)" % (length_difference, len(decoded_pcs)))
    else:
        print("Error Decoded has %d lines more than Spike (%d)" % (-length_difference, len(spike_pcs)))

if differences == 0 and length_difference == 0:
    print("Traces are identical")
else:
    print("%d content differences found" % differences)

if len(discarded_pcs) != 0:
    print("Discarded exceptions at", discarded_pcs)

exit(differences + abs(length_difference))
