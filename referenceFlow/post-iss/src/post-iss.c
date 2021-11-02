/*
 * SPDX-License-Identifier: BSD-2-Clause
 * SPDX-FileCopyrightText: Copyright 2019-2021 Siemens. All rights reserved.
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "post_inst_set_sim.h"

static char *config_file = NULL;
static char *input_file = NULL;

int main(int argc, char **argv)
{
  int opt;

  struct option long_options[] = {
      {"config_file", required_argument, 0, 'c'},
      {"input_file", required_argument, 0, 'i'},
      {"use_rv32_isa", no_argument, 0, 'r'},
  };
  int option_index = 0;

  while ((opt = getopt_long(argc, argv, "c:i:r", long_options, &option_index)) != -1)
  {
    switch (opt)
    {
    case 'c':
      config_file = optarg;
      break;

    case 'i':
      input_file = optarg;
      break;

    case 'r':
      set_rv_isa_32bit(true);
      break;
    }
  }

  if (NULL == config_file)
  {
    printf("No config file given\n");
    printf("use --config_file <config_file.ini> to parse a config file\n");
    exit(-1);
  }
  if (NULL == input_file)
  {
    printf("No input Instruction Set Simulation output file given\n");
    printf("use --input_file <program.spike_trace> to parse an ISS spike file\n");
    exit(-1);
  }

  assert(config_file != NULL);
  assert(input_file != NULL);

  if (!post_iss_parse_config(config_file))
  {
    printf("Config fail failed to parse\n");
    exit(-1);
  }

  process_iss_file(input_file);

  return 0;
}
