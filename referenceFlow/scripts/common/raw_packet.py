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

from common.utils import debug_print
from common import utils

class RawPacket:
    """
    Class for reading a single packet from a byte stream of data from a trace encoder.

    (See chapter 7 - Instruction Trace Encoder Output Packets
      In order to achieve best performance, actual packet lengths may be adjusted using
      'sign based compression'. At the very minimum this should be applied to the address
      field of format 1 and 2 packets, but ideally will be applied to the whole packet,
      regardless of format. This technique eliminates identical bits from the most significant
      end of the packet, and adjusts the length of the packet accordingly. A decoder receiving
      this shortened packet can reconstruct the original full-length packet by sign-extending
      from the most significant received bit.
      Where the payload length given in the following tables, or after applying sign-based
      compression, is not a multiple of whole bytes in length, the payload must be
      sign-extended to the nearest byte boundary.
    """

    def __init__(self, data):
        self.data = data
        self.bits = "".join(format(datum, "08b") for datum in reversed(data))
        assert len(self.bits) % 8 == 0
        self.bit = len(self.bits)
        self.bits_used = 0
        self.output = None # This is the dict that data will be read into

    def __len__(self):
        return len(self.data)

    def set_output(self, output):
        assert self.output is None
        self.output = output

    def extend_msb(self, nbits):
        msb = self.bits[0]
        assert nbits > 0
        self.bits = (msb * nbits) + self.bits

        # Adjust current bit being processed as extension made to the start of string
        self.bit += nbits
        if utils.debug:
            debug_print("%s bit pos %d extended msb %d-bits" % (self.bits, self.bit, nbits))
            debug_print(" " * self.bit + "^")

    def get_bits(self, field, nbits, is_hex=False):
        if self.output is None:
            print("Error: packet output has not been set")
            exit(1)

        if nbits == 0:
            return None
        # Check whether we need to decompress more bits (by sign-extension) to allow the
        # required field to be read
        if nbits > self.bit:
            self.extend_msb(nbits - self.bit)

        if utils.debug:
            msg = "get_bits(%d) = b%s" % (nbits, self.bits[self.bit - nbits : self.bit])
            if field is not None:
                msg += " -> %s" % field
            debug_print("b%s   %s" % (self.bits, msg))
            debug_print(" " * self.bit + "^")

        value = int(self.bits[self.bit - nbits : self.bit], 2)
        self.bit -= nbits
        self.bits_used += nbits
        if is_hex:
            self.output[field] = utils.as_hex(value, nbits)
        else:
            self.output[field] = value
        return value

    def check(self, msg=None):
        # Can only check that not more than 7-bits has not been used.
        if self.bit > 7:
            error = "Error: up to %d bits have not been assigned." % self.bit
            if msg is not None:
                error += " [%s]" % msg
            print(error)
            exit(1)
        if msg is not None:
            debug_print("Packet check for %s successful" % msg)
