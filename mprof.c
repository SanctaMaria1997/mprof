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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/shm.h>
#include <semaphore.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <elf.h>
#ifdef LINUX
#include <libdwarf/dwarf.h>
#elif defined(FREEBSD)
#include <dwarf.h>
#endif
#include <getopt.h>
#include "elf_util.h"
#include "mprof_util.h"
#include "args.h"
#include "mprof.h"
#include "dwarfy.h"

#ifdef FREEBSD
#define PTRACE_TRACEME PT_TRACE_ME
#define PTRACE_CONT PT_CONTINUE
#define PTRACE_GETREGS PT_GETREGS
#define PTRACE_PEEKDATA PT_READ_D
#define PTRACE_POKEDATA PT_WRITE_D
#define PTRACE_VM_ENTRY PT_VM_ENTRY
#else
#define r_
#endif

extern char **environ;
LibmprofSharedMem *LIBMPROF_SHARED_MEM;
int SHMID;
int LIBMPROF_NUM_PATCHED_LIBS;
Library *lookup_library(char *name);

FILE *MPROF_OUTPUT_FILE;
char MPROF_OUTPUT_FILE_NAME[256];

sem_t *MPROF_INSTANCE;
sem_t *MPROF_MUTEX;
sem_t *MPROF_MEM_MUTEX;

void patch_function(pid_t pid,unsigned long int orig,unsigned long int wrapper)
{
#ifdef LINUX
  ptrace(PTRACE_POKEDATA,pid,(caddr_t)orig,wrapper);
#elif defined(FREEBSD)
  int high,low;
  low = (int)(wrapper & 0xFFFFFFFF);
  high = (int)((wrapper & 0xFFFFFFFF00000000) >> 32);
  ptrace(PTRACE_POKEDATA,pid,(caddr_t)orig,low);
  ptrace(PTRACE_POKEDATA,pid,(caddr_t)(orig + 4),high);
#endif
}

void patch_mem_functions(pid_t pid,Library *destination,Library *source)
{
  char *libc_functions[] = {"malloc","calloc","realloc","free",""};
  char *gnu_functions[] = {"g_malloc","g_malloc0","g_realloc","g_try_malloc","g_try_malloc0","g_try_realloc","g_malloc_n","malloc0_n","g_realloc_n","g_free",""};

  char **functions;
  char patch[256];
  unsigned long int relocation;
  int i;
  
  if(LIBMPROF_SHARED_MEM->config.gnu)
    functions = gnu_functions;
  else
    functions = libc_functions;
  
  i = 0;
  
  while(0 != strcmp(functions[i],""))
  {
    strcpy(patch,"mprof");
    strcat(patch,"_");
    strcat(patch,functions[i]);
    
    if((relocation = get_elf_relocation(destination->elf,functions[i])))
      patch_function(pid,
                    relocation - get_elf_base_address(destination->elf) + destination->base_address,
                    get_elf_symbol(source->elf,patch) - get_elf_base_address(source->elf) + source->base_address);
    i++;
  }
}

void strip_so_version_num(char *st)
{
    int z = 0;
    while(st[z] != 0)
    {;
      if(st[z] == '.' && st[z+1] == 's' && st[z+2] == 'o')
      {
        st[z+3] = 0;
        break;
      }
      z++;
    }
}

#ifdef LINUX

void load_mem_regions(pid_t pid)
{
  FILE *vm_maps;
  char pid_str[32];
  char path[64];
  char module_path[512];
  char buff[512];
  int i,j,k;
  int bytes_read;
  char d[128];
  int line_offset;
  int file_offset;
  void *low_address;
  void *high_address;
  char c;
  
  i = 0;
  j = 0;
  k = 0;

  file_offset = 0;
  low_address = 0;
  high_address = 0;
  
  sprintf(pid_str,"%d",pid);
  strcpy(path,"/proc/");
  strcat(path,pid_str);
  strcat(path,"/maps");
  
  vm_maps = fopen(path,"rb");

  do
  {
    file_offset = 0;
    line_offset = 0;
    do
    {
      fscanf(vm_maps,"%c",&c);
      buff[file_offset] = c;
      file_offset++;
    } while(c != '\n' && !feof(vm_maps));
    
    buff[file_offset] = 0;
    
    module_path[0] = 0;
    sscanf(buff,"%lx-%lx %s %s %s %s %n",&low_address,&high_address,d,d,d,d,&bytes_read); 
    
    line_offset = bytes_read;
    
    if(buff[line_offset] == '/')
    {
        sscanf(buff + line_offset,"%s%n",module_path,&bytes_read);
        line_offset += bytes_read;

        while(buff[line_offset])
        {
            sscanf(buff + line_offset,"%c",d);
            line_offset++;
        }
    }
    
    for(j = 0; j < k; j++)
    {
      if(!strcmp(file_part(module_path),file_part(LIBMPROF_SHARED_MEM->libraries[j].name)))
        goto skip;
    }
    
    if(strlen(module_path) == 0)
        goto skip;
    
    LIBMPROF_SHARED_MEM->libraries[k].base_address = (unsigned long int)(low_address);
    
    strcpy(LIBMPROF_SHARED_MEM->libraries[k].name,file_part(module_path));
    
    strip_so_version_num(LIBMPROF_SHARED_MEM->libraries[k].name);
    
    k++;
    skip:
    k;

  } while(!feof(vm_maps)); 

  fclose(vm_maps);
}

#elif defined(FREEBSD)

void load_mem_regions(pid_t pid)
{
  struct ptrace_vm_entry entry;
  unsigned long int prev_start = 0;
  char *mmm = malloc(256);
  entry.pve_entry = 0;
  entry.pve_start = 0;
  entry.pve_path = mmm;
  int i,j,k;
  i = 0;
  j = 0;
  k = 0;
  
  do
  {
    prev_start = entry.pve_start;
    entry.pve_pathlen = 256;
    ptrace(PTRACE_VM_ENTRY,pid,(caddr_t)(&entry),0);
    
    for(j = 0; j < k; j++)
    {
      if(!strcmp(file_part(mmm),file_part(LIBMPROF_SHARED_MEM->libraries[j].name)))
        goto skip;
    }
    
    LIBMPROF_SHARED_MEM->libraries[k].base_address = (unsigned long int)(entry.pve_start);
    strcpy(LIBMPROF_SHARED_MEM->libraries[k].name,file_part(mmm));
    strip_so_version_num(LIBMPROF_SHARED_MEM->libraries[k].name);
    k++;
    skip:
    i++;

  } while(entry.pve_start != prev_start); 

}

#endif

int main(int argc,char **argv)
{
  pid_t pid;
  int result = 1;
  int status;
  char target_name[512];
  Library *target,*libmprof;
  /*OptionSpec available_options[] = {{"--stderr",0},{"-t",0},
                                     {"--call-sites",0},{"-c",0},
                                     {"--gnu",0},{"-g",0},
                                     {"--structs",0},{"-s",0},
                                     {"",0}};
                                     */
  Option *options;
  NonOption *non_options;
  int proj;
  int instance;
  
  int i,j;
  
  MPROF_MUTEX = sem_open("/mprof_mutex",O_CREAT,0666,1);
  MPROF_INSTANCE = sem_open("/mprof_instance",O_CREAT,0666,0);
  MPROF_MEM_MUTEX = sem_open("/MPROF_MEM_MUTEX",O_CREAT,0666,1);
  
  sem_getvalue(MPROF_INSTANCE,&instance);
  sem_getvalue(MPROF_MUTEX,&proj);
  sem_wait(MPROF_MUTEX);
  sem_getvalue(MPROF_MUTEX,&proj);

  sprintf(MPROF_OUTPUT_FILE_NAME,"tables.mprof.%d",instance);
  MPROF_OUTPUT_FILE = fopen(MPROF_OUTPUT_FILE_NAME,"w");
  fclose(MPROF_OUTPUT_FILE);
  
  SHMID = shmget(ftok(MPROF_OUTPUT_FILE_NAME,1),sizeof(LibmprofSharedMem),IPC_CREAT | 0666);
  LIBMPROF_SHARED_MEM = shmat(SHMID,0,0);
  sem_post(MPROF_MUTEX);

  memset(LIBMPROF_SHARED_MEM,0,sizeof(LibmprofSharedMem));
  
  LIBMPROF_NUM_PATCHED_LIBS = 0;

  OptionSpec available_options[] = {{"--stderr","-t",0},
                     {"--call-sites","-c",0},
                     {"--gnu","-g",0},
                     {"--structs","-s",0},
                     {"","",0}};
                     
  register_options(available_options);
  
  parse_options(argc,argv);
  options = get_options();
  non_options = get_non_options();
  
  i = 0;

  while(i < non_options[0].index && strlen(options[i].option))
  {
    if(option_is("--stderr",&options[i]))
    {
      printf("[mprof] Printing to terminal...\n");
      LIBMPROF_SHARED_MEM->config.output_to_stderr = 1;
    }
    else if(option_is("--call-sites",&options[i]))
    {
      printf("[mprof] Call sites enabled...\n");
      LIBMPROF_SHARED_MEM->config.call_sites = 1;
    }
    else if(option_is("--gnu",&options[i]))
    {
      printf("[mprof] Patching GNU glib memory management functions only...\n");
      LIBMPROF_SHARED_MEM->config.gnu = 1;
    }
    else if(option_is("--structs",&options[i]))
    {
      printf("[mprof] Printing corresponding source code structs...\n");
      LIBMPROF_SHARED_MEM->config.structs = 1;
    }
    i++;
  }
  
  strcpy(target_name,non_options[0].text);
  
  strcpy(LIBMPROF_SHARED_MEM->patched_lib_names[LIBMPROF_NUM_PATCHED_LIBS],target_name);
  LIBMPROF_NUM_PATCHED_LIBS++;
  
  switch(pid = fork())
  {
      case -1:
      {
          fprintf(stderr,"Unable to launch traced process; exiting.\n");
          exit(1);
      }
      case 0:
      {
        ptrace(PTRACE_TRACEME,0,0,0);
        putenv("LD_PRELOAD=/usr/local/lib/libmprof.so");
#ifdef LINUX
        execvpe(target_name,argv + non_options[0].index,environ);
#elif defined(FREEBSD)
        exect(target_name,argv + non_options[0].index,environ);
#endif
        fprintf(stderr,"[mprof] Unable to launch program (%s).\n",target_name);
        exit(1);
        break;
      }
      default:
      {
        waitpid(pid,&status,0);
        ptrace(PTRACE_CONT,pid,(caddr_t)1,0);
        waitpid(pid,&status,0);
        
        load_mem_regions(pid);
        
        libmprof = lookup_library("libmprof.so");
        target = lookup_library(target_name);
        
        target->elf = load_elf(find_file(file_part(target_name),"."));
        libmprof->elf = load_elf(find_file("libmprof.so","/usr/local/lib/"));
        
        if(target->elf == 0)
        {
          fprintf(stderr,"[mprof] Unable to load ELF file \"%s\".",target->name);
          exit(1);
        }
        
        if(libmprof->elf == 0)
        {
          fprintf(stderr,"[mprof] Unable to load ELF file \"%s\".",libmprof->name);
          exit(1);
        }
        
        patch_mem_functions(pid,target,libmprof);
        
        j = 0;
        while(strlen(LIBMPROF_SHARED_MEM->libraries[j].name))
        {
          if( strcmp(LIBMPROF_SHARED_MEM->libraries[j].name,"placeholder.so"))
          {
            
            LIBMPROF_SHARED_MEM->libraries[j].elf = load_elf(find_file(LIBMPROF_SHARED_MEM->libraries[j].name,"."));
            if(LIBMPROF_SHARED_MEM->libraries[j].elf == 0)
            {
              fprintf(stderr,"[mprof] Note: unable to locate shared object \"%s\" in current directory hierarchy.\n",LIBMPROF_SHARED_MEM->libraries[j].name);
              goto cont;
            }
            
            if(strcmp(LIBMPROF_SHARED_MEM->libraries[j].name,"libmprof.so"))
            {
              fprintf(stderr,"[mprof] Patching \"%s\"...\n",LIBMPROF_SHARED_MEM->libraries[j].name);

              patch_mem_functions(pid,&LIBMPROF_SHARED_MEM->libraries[j],libmprof);
            }
          }
          cont:
          j++;
        } 

        ptrace(PTRACE_CONT,pid,(caddr_t)1,0);
        
        for(;;)
        {
          
          waitpid(pid,&status,0);
        
          if(WIFSTOPPED(status))
          {
            ptrace(PTRACE_CONT,pid,(caddr_t)1,0);  
          }
          else if(WIFEXITED(status))
          {
            result = WEXITSTATUS(status);
            break;
          }
       }
     }
  }

  if(LIBMPROF_SHARED_MEM->config.output_to_stderr)
    remove(MPROF_OUTPUT_FILE_NAME);
  
  shmdt(LIBMPROF_SHARED_MEM);
  shmctl(SHMID,IPC_RMID,0);

  fprintf(stderr,"[mprof] Program exited with code %d.\n",result);
  return 0;
}

Library *lookup_library(char *name)
{
  int i = 0;

  while(strlen(LIBMPROF_SHARED_MEM->libraries[i].name))
  {
    if(!strcmp(file_part(LIBMPROF_SHARED_MEM->libraries[i].name),file_part(name)))
    {
      return &LIBMPROF_SHARED_MEM->libraries[i];
    }
    i++;
  }
  return 0;
}
  
