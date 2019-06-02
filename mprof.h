/*

BSD 2-Clause License

Copyright (c) 2019, SanctaMaria1997
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#ifndef MPROF_H
#define MPROF_H

#include "dwarfy.h"

#define LIBMPROF_MAX_NUM_PATCHED_LIBS 256
#define LIBMPROF_MAX_NUM_REGIONS 4096
#define LIBMPROF_MAX_NUM_LIBRARIES 1024

typedef struct
{
    char name[256];
    unsigned char *elf;
    DWARF_DATA *dwarf;
    unsigned long int base_address;
} Library;

typedef struct
{
  unsigned int call_sites;
  unsigned int output_to_stderr;
  unsigned int gnu;
  unsigned int structs;
} LibmprofConfig; 

typedef struct
{
  LibmprofConfig config;
  char patched_lib_names[LIBMPROF_MAX_NUM_LIBRARIES][256];
  Library libraries[LIBMPROF_MAX_NUM_LIBRARIES];
} LibmprofSharedMem;

#endif
