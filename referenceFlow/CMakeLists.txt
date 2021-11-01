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

cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
project(trace-encoder C)

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# additional build types ...
set(CMAKE_C_FLAGS_TCOV "-fprofile-arcs -ftest-coverage")
set(CMAKE_C_FLAGS_GPROF "-pg")                      ### enable gprof profiling
set(CMAKE_C_FLAGS_NDEBUG "-DNDEBUG")                ### disable assert()
set(CMAKE_C_FLAGS_NO_STATS "-UTE_WITH_STATISTICS")  ### disable statistics
set(CMAKE_C_FLAGS_FASTEST "-DNDEBUG -UTE_WITH_STATISTICS") ### disable assert + statistics

# comment out to disable statistics (and gain a small performance boot)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DTE_WITH_STATISTICS")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -g -O3 -Wall -Wextra -Werror")
set(LD_FLAGS "${LD_FLAGS}")

include_directories(${CMAKE_SOURCE_DIR}/common/inc)

####### Force valgrind to be run on all tests #######
# This MUST be set before CTest is included. The exitcode is needed otherwise CTest does not
# force the testing to exit correctly.
set(MEMORYCHECK_COMMAND_OPTIONS "--leak-check=full --track-origins=yes --trace-children=yes --error-exitcode=1")
include(CTest)

find_program(MEMORYCHECK_COMMAND NAMES valgrind)
####### End of Force valgrind to be run on all tests #######

if(CMAKE_TESTING_ENABLED)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCMAKE_TESTING_ENABLED")
endif()

add_subdirectory(common)
add_subdirectory(post-iss)
add_subdirectory(tests/unit)
add_subdirectory(riscv-disassembler)

install(PROGRAMS ${CMAKE_BINARY_DIR}/post-iss/post-iss
  DESTINATION bin)
