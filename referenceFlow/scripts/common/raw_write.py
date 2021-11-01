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

class RawWrite:
    """
    Class for writing a byte stream of data from a trace encoder.
    This class allows a bit array to be constructed one field at a time. The packet is
    then compressed and output to the data stream.

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

    def __init__(self, raw_out, msg_type, source, hex_fields, stats):
        self.raw_out = raw_out
        self.msg_type = msg_type
        self.source = source
        self.hex_fields = hex_fields
        self.stats = stats

        self.bit_array = ""
        # List of the fields already added to allow checking that fields are only added once
        self.fields_added = []

    def __len__(self):
        return len(self.bit_array)

    def add_bits(self, field, nbits):
        assert field not in self.fields_added, field
        self.fields_added.append(field)
        value = self.source[field]
        # Allow None values to be ignored to simplify the logic
        if value is not None and nbits != 0:
            debug_print("add_bits: %s=%s nbits=%d" % (field, value, nbits))
            if isinstance(value, str):
                assert field in self.hex_fields, field
                value = int(value, 16)
            format_str = "{0:0%db}" % nbits
            all_bits = format_str.format(value)
            bits = all_bits[-nbits:]  # Take the nbits required
            discard = all_bits[0:-nbits]
            if len(discard) != 0:  # Check we're only discarding sign bits
                assert (
                    bits[0] * len(discard) == discard
                ), "Field %s discards non sign bit data %s" % (field, discard)
            self.bit_array = bits + self.bit_array
        else:
            debug_print("add_bits: field %s IGNORED" % field)

    def compress_packet(self):
        def byte_padding():
            padding = 8 - (len(self.bit_array) & 0x7)
            return 0 if padding == 8 else padding

        msb = self.bit_array[0]
        array_len = len(self.bit_array)
        sign_len = 1
        assert sign_len < array_len
        while sign_len < array_len:
            if msb != self.bit_array[sign_len]:
                break
            sign_len += 1

        self.stats["nbits"] += len(self.bit_array) + byte_padding()
        debug_print("  Payload %3d %s" % (len(self.bit_array), self.bit_array))
        self.bit_array = self.bit_array[sign_len - 1 :]
        compressed_bits = len(self.bit_array)

        # Make sure it's a multiple of 8 bits
        self.bit_array = msb * byte_padding() + self.bit_array
        debug_print("     Sent %3d %s (Compressed %s-bits)" %
                    (len(self.bit_array), self.bit_array, compressed_bits))

        self.stats["nbits_compressed"] += len(self.bit_array)
        assert len(self.bit_array) % 8 == 0, len(self.bit_array)

    def output_packet(self):
        """
        Output the 1-byte header and the payload
        Header = [1-bit, 2-bit msg_type, 5-bit payload length in bytes]
        """
        byte_length = (len(self.bit_array) >> 3)
        header = byte_length
        assert header < 31
        header |= (self.msg_type << 5)
        self.byte_array = [header]
        self.byte_array.extend(
            [
                int(self.bit_array[8 * i : 8 * (i + 1)], 2)
                for i in reversed(range(byte_length))
            ]
        )

        self.raw_out.write(bytearray(self.byte_array))
