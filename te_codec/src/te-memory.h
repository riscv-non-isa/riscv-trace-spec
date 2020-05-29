/*
 * Copyright (c) 2011-2020 UltraSoC Technologies Limited
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


/*
 *-----------------------------------------------------
 * NOTE:
 *
 * Users of the code are expected to provide their own
 * implementation of a few generic high-level memory
 * management functions, used by the "te-elf-dis" code.
 * Including the completion with their own implementation
 * details of the membuf_t structure.
 *-----------------------------------------------------
 */


#ifndef TE_MEMORY_H
#define TE_MEMORY_H


#include <stddef.h>     /* required for size_t */


typedef struct
{
    void * data;    /* pointer to managed memory */
    /*
     * plus any other implementation-specific fields to manage
     * the memory pointed to by the void pointer 'data'.
     * e.g. bytes allocated in 'data'.
     */
} membuf_t;


/*
 * set of functions to initialize, grow and free the
 * managed memory in a 'membuf_t' structure.
 */
extern void membuf_init(
    membuf_t * buf);

extern size_t membuf_append(
    membuf_t * buf,
    size_t length,
    const void * data);

extern void membuf_free(
    membuf_t * buf);


/*
 * wrapper for strdup() ... but exit() if it fails
 */
extern char * strdup_or_die(
    const char * str);


#endif /* TE_MEMORY_H */
