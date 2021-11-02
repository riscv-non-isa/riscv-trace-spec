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

import csv

def as_hex(value, bit_width):
    """ Creates a hexadecimal string of a given bit width from the value provided """
    mask = (1 << bit_width) - 1
    return "%x" % (value & mask)

def twoscomp(value, bit_width):
    if value & (1 << (bit_width - 1)):
        return (value - (1 << bit_width))
    return value

def clog2(value):
    """ Ceiling of log2 """
    value -= 1
    result = 0
    while value > 0:
        result += 1
        value >>= 1
    return result

debug = False
init_called = False

def init_debug(dbg):
    global debug, init_called
    debug = dbg
    init_called = True

def debug_print(msg):
    """ Output the argument string if debugging is enabled """
    if not init_called:
        print("Error: init_debug has not been called")
        exit(1)
    if debug:
        print(msg)

class DictReaderInsensitive(csv.DictReader):
    """
    Force lower case field names when reading from CSV
    https://stackoverflow.com/questions/16937457/python-dictreader-how-to-make-csv-column-names-lowercase
    """

    @property
    def fieldnames(self):
        return [field.lower() for field in csv.DictReader.fieldnames.fget(self)]

    def next(self):
        return DictInsensitive(csv.DictReader.next(self))
