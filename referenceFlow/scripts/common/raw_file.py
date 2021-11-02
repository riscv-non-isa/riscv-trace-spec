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

from common.raw_packet import RawPacket
from common.utils import debug_print
from common import utils

class RawFile:
    """
    Class for reading packets from a byte stream of data from a trace encoder.
    """

    def __init__(self, raw_fd):
        self.raw_fd = raw_fd
        self.raw_data = raw_fd.read()
        self.packet_start = 0
        self.npackets = 0

    def has_data(self):
        return self.packet_start < len(self.raw_data)

    def get_header(self):
        header = self.raw_data[self.packet_start]
        packet_length = header & 0x1f # 5-bit length in bytes
        msg_type = (header >> 5) & 0x3
        return (msg_type, packet_length)

    def process_packet(self, proc):
        self.npackets += 1
        (msg_type, packet_length) = self.get_header()
        assert self.packet_start + packet_length < len(self.raw_data)
        packet = RawPacket(self.raw_data[self.packet_start + 1 : self.packet_start + 1 + packet_length])
        result = proc(msg_type, packet_length, packet)
        assert len(packet) == packet_length
        self.packet_start += packet_length + 1 # Header is 1 byte
        return result
