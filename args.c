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

#include "args.h"
#include <stdio.h>
#include <string.h>

OptionSpec *available_options;
Option options[MAX_NUM_OPTIONS];
NonOption non_options[MAX_NUM_NON_OPTIONS];

void register_options(OptionSpec *ao)
{
  available_options = ao;
}

int parse_options(int argc,char **argv)
{
  int valid_option = 0;
  int expect_arg = 0;
  int i,j,k,l;
  
  memset(options,0,MAX_NUM_OPTIONS * sizeof(Option));
  memset(non_options,0,MAX_NUM_NON_OPTIONS * sizeof(NonOption));
  
  i = j = k = l = 0;
  
  for(i = 1; i < argc; i++)
  {
    if(argv[i][0] == '-')
    {
      j = 0;
      valid_option = 0;
      while(strlen(available_options[j].name))
      {
        if(0 == strcmp(argv[i],available_options[j].name) || 0 == strcmp(argv[i],available_options[j].short_name))
        {
          valid_option = 1;
          break;
        }
        j++;
      }
      
      if(!valid_option)
      {
        return 0;
      }
      strcpy(options[k].option,argv[i]);
      options[k].index = i;
      
      if(available_options[j].takes_arg)
        expect_arg = 1;
      else
        k++;
    }
    else
    {
      if(expect_arg)
      {
        if(argv[i][0] == '-')
          return 0;
        strcpy(options[k].argument,argv[i]);
        k++;
        expect_arg = 0;
      }
      else
      {
        strcpy(non_options[l].text,argv[i]);
        non_options[l].index = i;
        l++;
      }
    }
  }
  return 1;
}

Option *get_options()
{
  return options;
}

NonOption *get_non_options()
{
  return non_options;
}

int option_is(char *name,Option *option)
{
  int i = 0;
  while(strlen(available_options[i].name))
  {
    if(0 == strcmp(name,available_options[i].name) || 0 == strcmp(name,available_options[i].short_name))
    {
      if(0 == strcmp(option->option,available_options[i].name) || 0 == strcmp(option->option,available_options[i].short_name))
      {
        return 1;
      }
    }
    i++;
  }
  return 0;
}
