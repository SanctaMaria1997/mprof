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

int handle_options(int argc,char **argv,OptionSpec *available_options,Option *options,NonOption *non_options)
{
  int valid_option = 0;
  int expect_arg = 0;
  int i,j,k,l;
  
  i = j = k = l = 0;
  
  for(i = 1; i < argc; i++)
  {
    if(argv[i][0] == '-')
    {
      j = 0;
      valid_option = 0;
      while(strlen(available_options[j].name))
      {
        if(!strcmp(argv[i],available_options[j].name))
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
