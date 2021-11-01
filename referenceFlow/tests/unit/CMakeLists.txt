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

include_directories(
    ${CHECK_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/post-iss/inc
    ${CMAKE_SOURCE_DIR}/riscv-disassembler/src
)

add_library(unity STATIC unity.c)

set(POST-ISS_TEST_SOURCES
    ${CMAKE_SOURCE_DIR}/post-iss/src/static_config_parser.c
    ${CMAKE_SOURCE_DIR}/riscv-disassembler/src/riscv-disas.c
    ${CMAKE_SOURCE_DIR}/post-iss/src/post_inst_set_sim.c
)

add_executable(test_utils test_utils.c)
target_link_libraries(test_utils unity common-trace)

add_executable(test_static_conf_parser test_static_conf_parser.c ${POST-ISS_TEST_SOURCES})
target_link_libraries(test_static_conf_parser unity riscv-disassembler)

add_executable(test_post_inst_set_sim test_post_inst_set_sim.c ${POST-ISS_TEST_SOURCES})
target_link_libraries(test_post_inst_set_sim unity riscv-disassembler)

enable_testing()

add_test(NAME test_utils COMMAND test_utils)
add_test(NAME test_static_conf_parser COMMAND test_static_conf_parser)
add_test(NAME test_post_inst_set_sim COMMAND test_post_inst_set_sim)
