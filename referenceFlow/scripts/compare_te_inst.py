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

def check_spike_trace_header(header):
    expected_length = 8
    if len(header) != expected_length:
        print("Error reading header expected %d entries got %d" % (expected_length, len(header)))
        exit(1)
    header_str = ','.join(header)
    if header_str != 'VALID,ADDRESS,INSN,PRIVILEGE,EXCEPTION,ECAUSE,TVAL,INTERRUPT':
        print("Error reading header %s" % header_str)
        exit(1)

def compare_te_inst(exp, new):
    assert len(exp) == len(new), "exp:%d new:%d" % (len(exp), len(new))

    differences = 0
    invalid = '999'
    # Expect the new file to have 999 entries (invalid data)
    entry = 0
    for exp_value, new_value in zip(exp, new):
        if new_value != invalid:
            if new_value != exp_value:
                differences += 1
                if total_differences < difference_limit:
                    print("[%s] %s not %s" % (header[entry], new_value, exp_value))
        entry += 1
    return differences

parser = argparse.ArgumentParser()
parser.add_argument("expected_te",
                    help="Expected trace file")
parser.add_argument("new_te",
                    help="New trace file")
parser.add_argument("--limit",
                    help="Limit number of differences reported")

args = parser.parse_args()
if not os.path.exists(args.expected_te):
    print("Unable to find the expected file %s" % args.expected_te)
    exit(1)
if not os.path.exists(args.new_te):
    print("Unable to find the new file %s" % args.new_te)
    exit(1)

# Only report the first n differences
difference_limit = 20
if args.limit:
    difference_limit = args.limit

total_differences = 0
line = 1
with open(args.expected_te) as expected_fd, open(args.new_te) as new_fd:
    expected_reader = csv.reader(expected_fd)
    new_reader = csv.reader(new_fd)
    is_header = True
    for exp, new in zip(expected_reader, new_reader):
        if is_header:
            is_header = False
            header = new
            continue
        new_differences = compare_te_inst(exp, new)
        if new_differences != 0:
            if total_differences < difference_limit:
                print("Difference line %d" % line)
                print("  ", exp)
                print("  ", new)
            total_differences += new_differences
        line += 1
