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

from .utils import debug, debug_print

class RawRead:
    """
    Class for reading a byte stream of data from a trace encoder.

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

    def __len__(self):
        return len(self.data)

    def get_bits(self, nbits):
        if nbits == 0:
            return None
        assert self.bit >= nbits, "%d %d" % (self.bit, nbits)
        if debug:
            debug_print(
                "get_bits %d:%s" % (nbits, self.bits[self.bit - nbits : self.bit])
            )
        value = int(self.bits[self.bit - nbits : self.bit], 2)
        self.bit -= nbits
        self.bits_used += nbits
        return value

    # Mark bits as being required
    def mark_bits(self, nbits):
        self.bits_used += nbits

    # Decompress the data if necessary using sign bit extension to the expected length
    def decompress(self):
        msb = self.bits[0]
        compressed_bits = self.bits_used - len(self.bits)
        if debug:
            debug_print(
                "Original %d-bits used %d-bits" % (len(self.bits), self.bits_used)
            )
            debug_print(self.bits)
            debug_print(" " * self.bit + "^")

        if compressed_bits > 0:
            self.bits = (msb * compressed_bits) + self.bits
        else:
            # In this case extra signs bits were used to pad the packet to next byte boundary
            padding = msb * (-compressed_bits)
            assert self.bits[0:-compressed_bits] == padding
            self.bits = self.bits[-compressed_bits:]

        assert self.bits_used == len(self.bits)

        # Adjust current bit being processed as uncompressed bits added to the start of string
        self.bit += compressed_bits
        if debug:
            debug_print("%s bit pos %d" % (self.bits, self.bit))
            debug_print(" " * self.bit + "^")

    def check(self):
        # Check that all of the bits have been used
        if self.bit != 0:
            print("Error: %d bits have not been assigned." % self.bit)
            exit(1)
