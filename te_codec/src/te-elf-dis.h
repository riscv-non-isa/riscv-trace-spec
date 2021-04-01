/*
 * SPDX-License-Identifier: BSD-2-Clause
 * SPDX-FileCopyrightText: Copyright 2020 Siemens. All rights reserved.
 *
 * Copyright 2020 Siemens
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


#ifndef TE_ELF_DIS_H
#define TE_ELF_DIS_H


#include <stdint.h>     /* required for uint64_t */


/*
 * If TE_INCLUDE_TE_MEMORY_H is defined, then use that
 * as the name of a user-provided header file to include
 * that declares the memory management functions.
 * Otherwise, use the built-in include file, which users
 * need to complete and provide an implementation.
 */
#if defined(TE_INCLUDE_TE_MEMORY_H)
#   include TE_INCLUDE_TE_MEMORY_H
#else
#   include "te-memory.h"   /* default include */
#endif  /* TE_INCLUDE_TE_MEMORY_H */


/* one 2-tuple (pair of fields) per disassembled line */
typedef struct
{
    uint64_t address;   /* disassembly address (the key) */
    const char * line;  /* disassembly line (the text) */
} te_elf_dis_tuple_t;


/* optional disassembly file used as input to trace-decoder */
typedef struct
{
    const char * elf_dis_name;  /* name of elf-dis file */
    size_t num_tuples;      /* number currently used */
    size_t max_tuples;      /* number currently allocated */
    membuf_t membuf;        /* array of te_elf_dis_tuple_t */
} te_elf_dis_file_t;


extern int te_read_one_elf_dis_file(
    te_elf_dis_file_t * const elf_dis,
    const char * const elf_dis_name);

extern void te_free_one_elf_dis_file(
    te_elf_dis_file_t * const elf_dis);

extern const te_elf_dis_tuple_t * te_find_one_elf_dis_tuple(
    const te_elf_dis_file_t * const elf_dis,
    const uint64_t address);


#endif /* TE_ELF_DIS_H */
