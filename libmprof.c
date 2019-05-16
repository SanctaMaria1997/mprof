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

#include <signal.h>
#include <fcntl.h>
#include <semaphore.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "dwarfy.h"
#include "mprof.h"
#include "libmprof.h"
#include "mprof_util.h"

RB_GENERATE(TransactionPointTree,TransactionPoint,TransactionPointLinks,compare_transaction_points);
RB_GENERATE(TransactionPathTree,TransactionPath,TransactionPathLinks,compare_transaction_paths_by_name);
RB_GENERATE(TransactionPathSortedTree,TransactionPathSorted,TransactionPathSortedLinks,compare_transaction_paths_by_leaked_bytes);
RB_GENERATE(MemoryBlockTree,MemoryBlock,MemoryBlockLinks,compare_memory_blocks_by_address);
RB_GENERATE(MemoryBlockSortedTree,MemoryBlockSorted,MemoryBlockSortedLinks,compare_memory_blocks_by_size);
RB_GENERATE(MemoryBreakdownTree,MemoryBreakdown,MemoryBreakdownLinks,compare_memory_breakdowns);
RB_GENERATE(FunctionBreakdownTree,FunctionBreakdown,FunctionBreakdownLinks,compare_function_breakdowns);

unsigned long int LIBMPROF_TOTAL_NUM_TRANSACTIONS;
unsigned long int LIBMPROF_NUM_MALLOCS;
unsigned long int LIBMPROF_NUM_CALLOCS;
unsigned long int LIBMPROF_NUM_REALLOCS;
unsigned long int LIBMPROF_NUM_FREES;
unsigned long int LIBMPROF_TOTAL_NUM_TRANSACTIONS;
unsigned long int LIBMPROF_TOTAL_BYTES_ALLOCATED;
unsigned long int LIBMPROF_TOTAL_BYTES_FREED;

unsigned long int LIBMPROF_NUM_ALLOCATIONS_SMALL;
unsigned long int LIBMPROF_NUM_ALLOCATIONS_MEDIUM;
unsigned long int LIBMPROF_NUM_ALLOCATIONS_LARGE;
unsigned long int LIBMPROF_NUM_ALLOCATIONS_XLARGE;
unsigned long int LIBMPROF_NUM_FREES_SMALL;
unsigned long int LIBMPROF_NUM_FREES_MEDIUM;
unsigned long int LIBMPROF_NUM_FREES_LARGE;
unsigned long int LIBMPROF_NUM_FREES_XLARGE;

unsigned long int LIBMPROF_TOTAL_NUM_BYTES_SMALL;
unsigned long int LIBMPROF_TOTAL_NUM_BYTES_MEDIUM;
unsigned long int LIBMPROF_TOTAL_NUM_BYTES_LARGE;
unsigned long int LIBMPROF_TOTAL_NUM_BYTES_XLARGE;

unsigned long int LIBMPROF_CURRENT_NUM_BYTES_SMALL;
unsigned long int LIBMPROF_CURRENT_NUM_BYTES_MEDIUM;
unsigned long int LIBMPROF_CURRENT_NUM_BYTES_LARGE;
unsigned long int LIBMPROF_CURRENT_NUM_BYTES_XLARGE;

int MPROF_OUTPUT_FILE;
char MPROF_OUTPUT_FILE_NAME[256];

int MPROF_DEBUGGER;
char MPROF_DEBUGGER_NAME[256];

sem_t *MPROF_INSTANCE;

LibmprofSharedMem *LIBMPROF_SHARED_MEM;
int SHMID;
long int LIBMPROF_REGION_BASE[LIBMPROF_MAX_NUM_REGIONS];
long int LIBMPROF_NUM_REGIONS;

TransactionPointTree_t TRANSACTION_POINTS;
MemoryBreakdownTree_t MEMORY_BREAKDOWNS;
FunctionBreakdownTree_t FUNCTION_BREAKDOWNS;

DWARF_DATAList_t DWARFY_PROGRAM;

void leak_report(void);

int compare_transaction_points(TransactionPoint *a1,TransactionPoint *a2)
{
  return a1->address - a2->address;
}

int compare_transaction_paths_by_name(TransactionPath *a1,TransactionPath *a2)
{
  return strcmp(a1->name,a2->name);
}

int compare_transaction_paths_by_leaked_bytes(TransactionPathSorted *a1,TransactionPathSorted *a2)
{
  return a2->current_bytes_allocated - a1->current_bytes_allocated;
}

int compare_memory_blocks_by_address(MemoryBlock *mb1,MemoryBlock *mb2)
{
  return mb1->address - mb2->address;
}

int compare_memory_blocks_by_size(MemoryBlockSorted *mb1,MemoryBlockSorted *mb2)
{
  return mb1->size - mb2->size;
}

int compare_memory_breakdowns(MemoryBreakdown *mb1,MemoryBreakdown *mb2)
{
  return mb1->size - mb2->size;
}

int compare_function_breakdowns(FunctionBreakdown *fb1,FunctionBreakdown *fb2)
{
  return strcmp(fb1->name,fb2->name);
}

void  __attribute__((constructor)) libmprof_init()
{
  int i = 0,j = 0,m = 0;
  int proj;
  int instance;
  char name[256];
  
  LIBMPROF_NUM_MALLOCS = LIBMPROF_NUM_CALLOCS = LIBMPROF_NUM_REALLOCS = LIBMPROF_NUM_FREES = 0;
  
  LIBMPROF_NUM_ALLOCATIONS_SMALL = LIBMPROF_NUM_ALLOCATIONS_MEDIUM = LIBMPROF_NUM_ALLOCATIONS_LARGE = LIBMPROF_NUM_ALLOCATIONS_XLARGE = LIBMPROF_NUM_FREES_SMALL = LIBMPROF_NUM_FREES_MEDIUM = LIBMPROF_NUM_FREES_LARGE = LIBMPROF_NUM_FREES_XLARGE = 0;
  
  LIBMPROF_TOTAL_NUM_BYTES_SMALL = LIBMPROF_TOTAL_NUM_BYTES_MEDIUM = LIBMPROF_TOTAL_NUM_BYTES_LARGE = LIBMPROF_TOTAL_NUM_BYTES_XLARGE = 0;
  
  LIBMPROF_CURRENT_NUM_BYTES_SMALL = LIBMPROF_CURRENT_NUM_BYTES_MEDIUM = LIBMPROF_CURRENT_NUM_BYTES_LARGE = LIBMPROF_CURRENT_NUM_BYTES_XLARGE = 0;
  
  LIBMPROF_TOTAL_NUM_TRANSACTIONS = 0;
  LIBMPROF_TOTAL_BYTES_ALLOCATED = 0;
  
  
  RB_INIT(&TRANSACTION_POINTS);
  RB_INIT(&MEMORY_BREAKDOWNS);
  RB_INIT(&FUNCTION_BREAKDOWNS);

  MPROF_INSTANCE = sem_open("/mprof_instance",O_CREAT,0666,0);
  sem_getvalue(MPROF_INSTANCE,&instance);
  
  sprintf(MPROF_OUTPUT_FILE_NAME,"tables.mprof.%d",instance);
  SHMID = shmget(ftok(MPROF_OUTPUT_FILE_NAME,1),sizeof(LibmprofSharedMem),0666);
  LIBMPROF_SHARED_MEM = shmat(SHMID,0,0);
  
  sprintf(MPROF_DEBUGGER_NAME,"mprof_debugger.%d",instance);
  MPROF_DEBUGGER = open(MPROF_DEBUGGER_NAME,O_RDWR);
    
  if(LIBMPROF_SHARED_MEM->config.output_to_stderr)
    MPROF_OUTPUT_FILE = MPROF_DEBUGGER;
  else
  {
    MPROF_OUTPUT_FILE = open(MPROF_OUTPUT_FILE_NAME,O_WRONLY);
    //perror("lala");
  }
  
  sem_post(MPROF_INSTANCE);
  raise(SIGTRAP);
  
  while(strlen(LIBMPROF_SHARED_MEM->libraries[i].name))
  {
    if(LIBMPROF_SHARED_MEM->libraries[i].name[0] != '/')
    {
      strcpy(name,file_part(LIBMPROF_SHARED_MEM->libraries[i].name));
      if(strlen(find_file(name,".")))
      {
        LIBMPROF_SHARED_MEM->libraries[i].dwarf = load_dwarf(find_file(name,"."),LIBMPROF_SHARED_MEM->libraries[i].base_address);
        j = 0;
        while(strlen(LIBMPROF_SHARED_MEM->patched_lib_names[j]))
        {
          if(LIBMPROF_SHARED_MEM->libraries[i].dwarf == 0 && !strcmp(name,file_part(LIBMPROF_SHARED_MEM->patched_lib_names[j])))
          {
            fprintf(stderr,"[mprof] Unable to load DWARF debug information from object \"%s\". Consider recompiling with -g to generate debug information.",LIBMPROF_SHARED_MEM->libraries[i].name);
            exit(1);
          }
          j++;
        }
      }
    }
    i++;
  }
  
  i = 0;
  m = 0;
  DwarfyCompilationUnit *compilation_unit;
  
  while(strlen(LIBMPROF_SHARED_MEM->libraries[i].name))
  {
    if(LIBMPROF_SHARED_MEM->libraries[i].dwarf)
    {
      LIST_FOREACH(compilation_unit,&LIBMPROF_SHARED_MEM->libraries[i].dwarf->compilation_units,linkage)
      m += compilation_unit->has_main_function;
    }
    i++;
  }
  
  if(m == 0)
  {
    fprintf(stderr,"[mprof] Unable to load DWARF debug information from object. Consider recompiling with -g to generate debug information.");
    exit(1);
  }
}

TransactionPoint *create_transaction_point(int transaction_type,long int address)
{
  TransactionPoint *transaction_point;
  transaction_point = malloc(sizeof(TransactionPoint));
  memset(transaction_point,0,sizeof(TransactionPoint));
  transaction_point->transaction_type = transaction_type;
  transaction_point->address = address;
  RB_INIT(&transaction_point->paths);
  RB_INSERT(TransactionPointTree,&TRANSACTION_POINTS,transaction_point);
  
  return transaction_point;
}

TransactionPath *create_transaction_path(int transaction_type,char *name,TransactionPoint *transaction_point)
{
  TransactionPath *transaction_path;
  
  transaction_path = malloc(sizeof(TransactionPath));
  memset(transaction_path,0,sizeof(TransactionPath));
  transaction_path->name = malloc(strlen(name) + 1);
  transaction_path->transaction_point = transaction_point;
  strcpy(transaction_path->name,name);
  RB_INIT(&transaction_path->memory_blocks);

  RB_INSERT(TransactionPathTree,&transaction_point->paths,transaction_path);
  
  return transaction_path;
}

MemoryBlock *create_memory_block(unsigned long int address,size_t size,TransactionPath *transaction_path)
{
  MemoryBlock *memory_block;
  memory_block = malloc(sizeof(MemoryBlock));
  memory_block->address = address;
  memory_block->size = size;
  memory_block->path = transaction_path;
  
  RB_INSERT(MemoryBlockTree,&transaction_path->memory_blocks,memory_block);
  
  return memory_block;
}

void trace_(unsigned long int *frame_pointer,char **trace,int length,int depth)
{
  DwarfyFunction *function;
  DwarfyCompilationUnit *compilation_unit;
  DwarfySourceRecord *source_record;
  unsigned long int address;
  char location[256];
  char *new_trace;
  char *elipsis = "...";  
  Dl_info info;

  address = *(frame_pointer + 1);
  
  if(0 == dladdr(address,&info))
  {
    puts("[mprof] Invalid frame pointer detected; consider recompiling this program without optimisations.");
    exit(1);
  }
  
  function = address_to_function(address);
  compilation_unit = address_to_compilation_unit(address);
  source_record = address_to_source_record(address);

  if(LIBMPROF_SHARED_MEM->config.call_sites)
    sprintf(location," [%s:%d] ",compilation_unit->file_names[source_record->file - 1],source_record->line_number);
  else
    sprintf(location," ");
  
  new_trace = malloc(length + strlen(function->name) + strlen(location) + 8);
  strcpy(new_trace,function->name);
  strcat(new_trace,"()");
  strcat(new_trace,location);
  if(depth > 0)
    strcat(new_trace,"-> ");
  strcat(new_trace,*trace);
  free(*trace);
  *trace = new_trace;
  
  if(depth == MPROF_TRACE_DEPTH - 1)
  {
    if(strcmp(function->name,"main"))
    {
      new_trace = malloc(strlen(*trace) + strlen(elipsis) + 2);
      sprintf(new_trace,"%s ",elipsis);
      strcat(new_trace,*trace);
      free(*trace);
      *trace = new_trace;
    }
  }
  else if(strcmp(function->name,"main"))
  {
    trace_((unsigned long int*)*frame_pointer,trace,strlen(*trace),depth + 1);
  }
}

void update_alloc_bins(size_t size)
{
  if(size <= 32)
  {
    LIBMPROF_NUM_ALLOCATIONS_SMALL++;
    LIBMPROF_TOTAL_NUM_BYTES_SMALL += size;
    LIBMPROF_CURRENT_NUM_BYTES_SMALL += size;
  }
  else if(size <= 256)
  {
    LIBMPROF_NUM_ALLOCATIONS_MEDIUM++;
    LIBMPROF_TOTAL_NUM_BYTES_MEDIUM += size;
    LIBMPROF_CURRENT_NUM_BYTES_MEDIUM += size;
  }
  else if(size <= 2048)
  {
    LIBMPROF_NUM_ALLOCATIONS_LARGE++;
    LIBMPROF_TOTAL_NUM_BYTES_LARGE += size;
    LIBMPROF_CURRENT_NUM_BYTES_LARGE += size;
  }
  else
  {
    LIBMPROF_NUM_ALLOCATIONS_XLARGE++;
    LIBMPROF_TOTAL_NUM_BYTES_XLARGE += size;
    LIBMPROF_CURRENT_NUM_BYTES_XLARGE += size;
  }
}

void update_free_bins(size_t size)
{
  if(size <= 32)
  {
    LIBMPROF_NUM_FREES_SMALL++;
    LIBMPROF_CURRENT_NUM_BYTES_SMALL -= size;
  }
  else if(size <= 256)
  {
    LIBMPROF_NUM_FREES_MEDIUM++;
    LIBMPROF_CURRENT_NUM_BYTES_MEDIUM -= size;
  }
  else if(size <= 2048)
  {
    LIBMPROF_NUM_FREES_LARGE++;
    LIBMPROF_CURRENT_NUM_BYTES_LARGE -= size;
  }
  else
  {
    LIBMPROF_NUM_FREES_XLARGE++;
    LIBMPROF_CURRENT_NUM_BYTES_XLARGE -= size;
  }
}

void update_memory_breakdowns_with_alloc(size_t size)
{
  MemoryBreakdown *memory_breakdown;
  MemoryBreakdown match_memory_breakdown;
  
  match_memory_breakdown.size = size;
  
  if(0 == (memory_breakdown = RB_FIND(MemoryBreakdownTree,&MEMORY_BREAKDOWNS,&match_memory_breakdown)))
  {
    memory_breakdown = malloc(sizeof(MemoryBreakdown));
    memset(memory_breakdown,0,sizeof(MemoryBreakdown));
    memory_breakdown->size = size;
    RB_INSERT(MemoryBreakdownTree,&MEMORY_BREAKDOWNS,memory_breakdown);
  }
  
  memory_breakdown->total_num_allocs++;
  memory_breakdown->current_bytes_allocated += size;
  memory_breakdown->total_bytes_allocated += size;
  
}

void update_memory_breakdowns_with_free(size_t size)
{
  MemoryBreakdown *memory_breakdown;
  MemoryBreakdown match_memory_breakdown;
  
  match_memory_breakdown.size = size;
    
  if(0 == (memory_breakdown = RB_FIND(MemoryBreakdownTree,&MEMORY_BREAKDOWNS,&match_memory_breakdown)))
  {
    memory_breakdown = malloc(sizeof(MemoryBreakdown));
    memset(memory_breakdown,0,sizeof(MemoryBreakdown));
    memory_breakdown->size = size;
  }
  
  memory_breakdown->current_bytes_allocated -= size;
  memory_breakdown->total_num_frees++;
  
}

void update_function_breakdowns_with_alloc(unsigned long int *frame_pointer,size_t size)
{
  DwarfyFunction *function;
  unsigned long int address;
  FunctionBreakdown *function_breakdown;
  FunctionBreakdown match_function_breakdown;

  address = *(frame_pointer + 1);
  function = address_to_function(address);
  match_function_breakdown.name = function->name;
  
  if(0 == (function_breakdown = RB_FIND(FunctionBreakdownTree,&FUNCTION_BREAKDOWNS,&match_function_breakdown)))
  {
    function_breakdown = malloc(sizeof(FunctionBreakdown));
    memset(function_breakdown,0,sizeof(FunctionBreakdown));
    function_breakdown->name = malloc(strlen(function->name) + 1);
    strcpy(function_breakdown->name,function->name);
    RB_INSERT(FunctionBreakdownTree,&FUNCTION_BREAKDOWNS,function_breakdown);
  }
  
  function_breakdown->num_calls++;
  function_breakdown->total_bytes_allocated += size;
  function_breakdown->current_bytes_allocated += size;  
  
  if(size <= 32)
  {
    function_breakdown->num_allocations_small++;
    function_breakdown->total_small_bytes_allocated += size;
    function_breakdown->current_small_bytes_allocated += size;
  }
  else if(size <= 256)
  {
    function_breakdown->num_allocations_medium++;
    function_breakdown->total_medium_bytes_allocated += size;
    function_breakdown->current_medium_bytes_allocated += size;
  }
  else if(size <= 2048)
  {
    function_breakdown->num_allocations_large++;
    function_breakdown->total_large_bytes_allocated += size;
    function_breakdown->current_large_bytes_allocated += size;
  }
  else
  {
    function_breakdown->num_allocations_xlarge++;
    function_breakdown->total_xlarge_bytes_allocated += size;
    function_breakdown->current_xlarge_bytes_allocated += size;
  }
}

void update_function_breakdowns_with_free(unsigned long int *frame_pointer,size_t size)
{
  DwarfyFunction *function;
  unsigned long int address;
  FunctionBreakdown *function_breakdown;
  FunctionBreakdown match_function_breakdown;

  address = *(frame_pointer + 1);
  function = address_to_function(address);
  match_function_breakdown.name = function->name;
  
  if(0 == (function_breakdown = RB_FIND(FunctionBreakdownTree,&FUNCTION_BREAKDOWNS,&match_function_breakdown)))
  {
    function_breakdown = malloc(sizeof(FunctionBreakdown));
    memset(function_breakdown,0,sizeof(FunctionBreakdown));
    function_breakdown->name = malloc(strlen(function->name) + 1);
    strcpy(function_breakdown->name,function->name);
    RB_INSERT(FunctionBreakdownTree,&FUNCTION_BREAKDOWNS,function_breakdown);
  }
  
  function_breakdown->num_calls++;
  function_breakdown->current_bytes_allocated -= size;

  if(size <= 32)
  {
    function_breakdown->current_small_bytes_allocated -= size;
  }
  else if(size <= 256)
  {
    function_breakdown->current_medium_bytes_allocated -= size;
  }
  else if(size <= 2048)
  {
    function_breakdown->current_large_bytes_allocated -= size;
  }
  else
  {
    function_breakdown->current_xlarge_bytes_allocated -= size;
  }
}

void *malloc_wrapper(size_t size)
{  
  void *result;
  long int return_address = 0;
  long int transaction_address;
  char *trace;
  unsigned long int *frame_pointer;
  TransactionPoint match_transaction_point;
  TransactionPoint *transaction_point;
  TransactionPath match_transaction_path;
  TransactionPath *transaction_path;
  MemoryBlock *memory_block;

  __asm__
  (
    "movq %%rbp, %0\n"
    : [frame_pointer] "=r"(frame_pointer)
  );
  
  trace = malloc(1);
  *trace = 0;
  trace_(frame_pointer,&trace,strlen(trace) + 1,0);
  
  return_address = *(frame_pointer + 1);
  
  if(LIBMPROF_SHARED_MEM->config.call_sites)
    match_transaction_point.address = return_address;
  else
    match_transaction_point.address = (address_to_function(return_address))->address;
  
  match_transaction_path.name = malloc(strlen(trace) + 1);
  strcpy(match_transaction_path.name,trace);

  if(0 == (transaction_point = RB_FIND(TransactionPointTree,&TRANSACTION_POINTS,&match_transaction_point)))
  {
    transaction_point = create_transaction_point(TRANSACTION_TYPE_GENERIC,match_transaction_point.address);
    transaction_path = create_transaction_path(TRANSACTION_TYPE_GENERIC,trace,transaction_point);
  }
  else if(0 == (transaction_path = RB_FIND(TransactionPathTree,&transaction_point->paths,&match_transaction_path)))
  {
    transaction_path = create_transaction_path(TRANSACTION_TYPE_GENERIC,trace,transaction_point);
  }

  transaction_path->current_num_transactions++;
  transaction_path->current_bytes_allocated += size;
  transaction_path->total_num_transactions++;
  transaction_path->total_bytes_allocated += size;

  result = malloc(size);
  
  memory_block = create_memory_block((unsigned long int)result,size,transaction_path);

  LIBMPROF_TOTAL_NUM_TRANSACTIONS++;
  LIBMPROF_NUM_MALLOCS++;
  LIBMPROF_TOTAL_BYTES_ALLOCATED += size;
  update_alloc_bins(size);
  update_memory_breakdowns_with_alloc(size);
  update_function_breakdowns_with_alloc(frame_pointer,size);
  
  free(trace);
  free(match_transaction_path.name);
  return result;
}

void *calloc_wrapper(size_t num,size_t size)
{
  void *result;
  long int return_address = 0;
  long int transaction_address;
  char *trace;
  unsigned long int *frame_pointer;
  TransactionPoint match_transaction_point;
  TransactionPoint *transaction_point;
  TransactionPath match_transaction_path;
  TransactionPath *transaction_path;
  MemoryBlock *memory_block;
  
  __asm__
  (
    "movq %%rbp, %0\n"
    : [frame_pointer] "=r"(frame_pointer)
  );
  
  trace = malloc(1);
  strcpy(trace,"");
  
  trace_(frame_pointer,&trace,strlen(trace) + 1,0);

  return_address = *(frame_pointer + 1);
  
  if(LIBMPROF_SHARED_MEM->config.call_sites)
    match_transaction_point.address = return_address;
  else
    match_transaction_point.address = (address_to_function(return_address))->address;
  
  match_transaction_path.name = malloc(strlen(trace) + 1);
  strcpy(match_transaction_path.name,trace);

  if(0 == (transaction_point = RB_FIND(TransactionPointTree,&TRANSACTION_POINTS,&match_transaction_point)))
  {
    transaction_point = create_transaction_point(TRANSACTION_TYPE_GENERIC,match_transaction_point.address);
    transaction_path = create_transaction_path(TRANSACTION_TYPE_GENERIC,trace,transaction_point);
  }
  else if(0 == (transaction_path = RB_FIND(TransactionPathTree,&transaction_point->paths,&match_transaction_path)))
    transaction_path = create_transaction_path(TRANSACTION_TYPE_GENERIC,trace,transaction_point);

  transaction_path->current_num_transactions++;
  transaction_path->current_bytes_allocated += num * size;
  transaction_path->total_num_transactions++;
  transaction_path->total_bytes_allocated += num * size;

  result = calloc(num,size);
  
  memory_block = create_memory_block((unsigned long int)result,num * size,transaction_path);

  LIBMPROF_TOTAL_NUM_TRANSACTIONS++;
  LIBMPROF_NUM_CALLOCS++;
  LIBMPROF_TOTAL_BYTES_ALLOCATED += num * size;
  update_alloc_bins(num * size);
  update_memory_breakdowns_with_alloc(num * size);
  update_function_breakdowns_with_alloc(frame_pointer,num * size);
  
  free(trace);
  free(match_transaction_path.name);
  
  return result;
}

void *realloc_wrapper(void *ptr,size_t size)
{
  void *result;
  long int return_address = 0;
  long int size_difference = 0;
  unsigned long int *frame_pointer;
  char *trace;
  unsigned long int block_size_increase;
  TransactionPoint match_transaction_point;
  TransactionPoint *transaction_point;
  TransactionPath match_transaction_path;
  TransactionPath *transaction_path;
  MemoryBlock *memory_block,match_memory_block;
  match_memory_block.address = (unsigned long int)ptr;
  
  __asm__
  (
    "movq %%rbp, %0\n"
    : [frame_pointer] "=r"(frame_pointer)
  );
  
  trace = malloc(1);
  strcpy(trace,"");
  
  trace_(frame_pointer,&trace,strlen(trace) + 1,0);

  return_address = *(frame_pointer + 1);
  
  memory_block = 0;
  
  RB_FOREACH(transaction_point,TransactionPointTree,&TRANSACTION_POINTS)
  {
    RB_FOREACH(transaction_path,TransactionPathTree,&transaction_point->paths)
    {
        if((memory_block = RB_FIND(MemoryBlockTree,&transaction_path->memory_blocks,&match_memory_block)))
          goto exit;
    }
  }
  
  exit:
  
  if(memory_block == 0)
  {
    free(trace);
    free(match_transaction_path.name);
    return realloc(ptr,size);
  }
  
  size_difference = ((long int)size) - ((long int)(memory_block->size));
  
  if(LIBMPROF_SHARED_MEM->config.call_sites)
    match_transaction_point.address = return_address;
  else
    match_transaction_point.address = (address_to_function(return_address))->address;
  
  match_transaction_path.name = malloc(strlen(trace) + 1);
  strcpy(match_transaction_path.name,trace);
  
  if(0 == (transaction_point = RB_FIND(TransactionPointTree,&TRANSACTION_POINTS,&match_transaction_point)))
  {
    transaction_point = create_transaction_point(TRANSACTION_TYPE_GENERIC,match_transaction_point.address);
    transaction_path = create_transaction_path(TRANSACTION_TYPE_GENERIC,trace,transaction_point);
  }
  
  if(0 == (transaction_path = RB_FIND(TransactionPathTree,&transaction_point->paths,&match_transaction_path)))
    transaction_path = create_transaction_path(TRANSACTION_TYPE_GENERIC,trace,transaction_point);

  if(transaction_path != memory_block->path)
  {
    RB_REMOVE(MemoryBlockTree,&memory_block->path->memory_blocks,memory_block);
    memory_block->path->current_bytes_allocated -= memory_block->size;
    memory_block->path->current_num_transactions--;
    RB_INSERT(MemoryBlockTree,&transaction_path->memory_blocks,memory_block);
  } 
  
  transaction_path->current_bytes_allocated += size;
  transaction_path->total_bytes_allocated += size;
  transaction_path->current_num_transactions++;
  transaction_path->total_num_transactions++;

  result = realloc(ptr,size);
  
  memory_block->address = (unsigned long int)result;
  memory_block->size = size;
  memory_block->path = transaction_path;
  
  block_size_increase = size_difference > 0 ? size_difference : 0;

  LIBMPROF_TOTAL_NUM_TRANSACTIONS++;
  LIBMPROF_NUM_REALLOCS++;
  LIBMPROF_TOTAL_BYTES_ALLOCATED += block_size_increase;
  update_alloc_bins(block_size_increase);
  update_memory_breakdowns_with_alloc(block_size_increase);
  update_function_breakdowns_with_alloc(frame_pointer,block_size_increase);
  
  free(trace);
  free(match_transaction_path.name);
  
  return result;
}

void free_wrapper(void *ptr)
{
  MemoryBlock match;
  MemoryBlock *memory_block;
  TransactionPoint *transaction_point;
  TransactionPath *transaction_path;
  TransactionPoint match_transaction_point;
  TransactionPath *orig_transaction_path;
  TransactionPoint *orig_transaction_point;
  TransactionPath match_transaction_path;
  long int return_address = 0;
  char *trace;
  unsigned long int *frame_pointer;
  
  __asm__
  (
    "movq %%rbp, %0\n"
    : [frame_pointer] "=r"(frame_pointer)
  );
  
  trace = malloc(1);
  *trace = 0;
  trace_(frame_pointer,&trace,strlen(trace) + 1,0);

  return_address = *(frame_pointer + 1);
  
  match_transaction_path.name = malloc(strlen(trace) + 1);
  strcpy(match_transaction_path.name,trace);
  if(LIBMPROF_SHARED_MEM->config.call_sites)
    match_transaction_point.address = return_address;
  else
    match_transaction_point.address = (address_to_function(return_address))->address;
  match.address = (unsigned long int)ptr;
  
  if(0 == (transaction_point = RB_FIND(TransactionPointTree,&TRANSACTION_POINTS,&match_transaction_point)))
  {
    transaction_point = create_transaction_point(TRANSACTION_TYPE_FREE,match_transaction_point.address);
    transaction_path = create_transaction_path(TRANSACTION_TYPE_FREE,trace,transaction_point);
  }
  else if(0 == (transaction_path = RB_FIND(TransactionPathTree,&transaction_point->paths,&match_transaction_path)))
    transaction_path = create_transaction_path(TRANSACTION_TYPE_FREE,trace,transaction_point);  
  
  RB_FOREACH(orig_transaction_point,TransactionPointTree,&TRANSACTION_POINTS)
  {
    RB_FOREACH(orig_transaction_path,TransactionPathTree,&orig_transaction_point->paths)
    {
        
      if((memory_block = RB_FIND(MemoryBlockTree,&orig_transaction_path->memory_blocks,&match)))
      {
        orig_transaction_path->current_num_transactions--;
        orig_transaction_path->current_bytes_allocated -= memory_block->size;
        transaction_path->total_num_frees++;
        transaction_path->total_bytes_freed += memory_block->size;
        RB_REMOVE(MemoryBlockTree,&orig_transaction_path->memory_blocks,memory_block);
        LIBMPROF_TOTAL_BYTES_FREED += memory_block->size;
        update_free_bins(memory_block->size);
        update_memory_breakdowns_with_free(memory_block->size);
        update_function_breakdowns_with_free(frame_pointer,memory_block->size);
        free(memory_block);
    
      }
    }
  }
  
  LIBMPROF_NUM_FREES++;
  
  free(trace);
  free(match_transaction_path.name);
  
  free(ptr);
}

__attribute__((destructor)) void libmprof_final()
{
  char buffer[512];
  fprintf(stderr,"\n[mprof] MEMORY STATISTICS\n");
  
  memory_breakdown_table_out();
  leak_table_out();
  function_breakdown_table_out();

  sprintf(buffer,"[mprof] Memory usage summary:\n");
  write(MPROF_DEBUGGER,buffer,strlen(buffer));
  
  sprintf(buffer,"[mprof] Program allocated %ld block(s)\n",LIBMPROF_TOTAL_NUM_TRANSACTIONS);
  write(MPROF_DEBUGGER,buffer,strlen(buffer));
  
  sprintf(buffer,"[mprof] (malloc: %ld, calloc: %ld, realloc: %ld)\n",LIBMPROF_NUM_MALLOCS,LIBMPROF_NUM_CALLOCS,LIBMPROF_NUM_REALLOCS);
  write(MPROF_DEBUGGER,buffer,strlen(buffer));
  
  sprintf(buffer,"[mprof] Program freed %ld block(s)\n",LIBMPROF_NUM_FREES);
  write(MPROF_DEBUGGER,buffer,strlen(buffer));
  
  if(0 == LIBMPROF_SHARED_MEM->config.output_to_stderr)
  {
    sprintf(buffer,"[mprof] For detailed memory usage statistics, consult the file \"%s\".\n",MPROF_OUTPUT_FILE_NAME);
    write(MPROF_DEBUGGER,buffer,strlen(buffer));
  }

  shmdt(LIBMPROF_SHARED_MEM);
  close(MPROF_OUTPUT_FILE);
  close(MPROF_DEBUGGER);
}

DwarfySourceRecord *address_to_source_record(unsigned long int address)
{
  DwarfyObjectRecord match_location_record;
  DwarfyCompilationUnit *compilation_unit;
  DwarfyObjectRecord *object_record;
  DwarfySourceRecord *source_record;

  compilation_unit = address_to_compilation_unit(address);
  
  match_location_record.address = address;
  
  do
  {
    address--;
    match_location_record.address = address;
    object_record = RB_FIND(DwarfyObjectRecordTree,&compilation_unit->line_numbers,&match_location_record);
  } while(object_record == 0);
  
  return source_record = LIST_FIRST(&object_record->source_records);
}

DwarfyFunction *address_to_function(unsigned long int address)
{
  DwarfyFunction *function = 0;
  DwarfyFunction match_function;
  DwarfyCompilationUnit *compilation_unit;
  
  compilation_unit = address_to_compilation_unit(address);
  
  function = 0;
  
  do
  {
    address--;
    match_function.address = address;
    function = RB_FIND(DwarfyFunctionTree,&compilation_unit->functions,&match_function);
  } while (!function);

  return function;
}

DwarfyCompilationUnit *address_to_compilation_unit(unsigned long int address)
{
  DwarfyObjectRecord match_location_record;
  DwarfyCompilationUnit *compilation_unit;
  DwarfySourceRecord *source_record;
  DwarfyObjectRecord *object_record;
  int matched = 0;
  int i;
  int j = 0;
  
  for(;;)
  {
    address--;
    match_location_record.address = address;
    
    i = 0;
    while(strlen(LIBMPROF_SHARED_MEM->libraries[i].name))
    {
      if(LIBMPROF_SHARED_MEM->libraries[i].dwarf)
      {
        LIST_FOREACH(compilation_unit,&LIBMPROF_SHARED_MEM->libraries[i].dwarf->compilation_units,linkage)
        {
          if((object_record = RB_FIND(DwarfyObjectRecordTree,&compilation_unit->line_numbers,&match_location_record)))
            return compilation_unit;
        }
      }
      
      i++;
    }
    
  }
  
  return 0;
  
}

char *percentage_as_string(unsigned long int numerator,unsigned long int denominator,char *buffer)
{
  double percentage;
  
  if(denominator == 0)
  {
    strcpy(buffer,"-");
    return buffer;
  }
  percentage = ((double)numerator) / ((double)denominator) * 100.0;
  
  if(percentage - floor(percentage) < 0.5)
    percentage = floor(percentage);
  else
    percentage = ceil(percentage);
  
  sprintf(buffer,"%lu",(unsigned long int)percentage);
  
  return buffer;
}

void memory_breakdown_table_out()
{
  DwarfyCompilationUnit *compilation_unit;
  DwarfyStruct *struct_;
  MemoryBreakdown *memory_breakdown;
  char buffer[512];
  char percentage1_buff[4];
  char percentage2_buff[4];
  char *struct_list;
  int struct_list_length;
  int i;
  
  sprintf(buffer,"[mprof] TABLE 1: ALLOCATION BINS\n\n");
  write(MPROF_OUTPUT_FILE,buffer,strlen(buffer));
  sprintf(buffer,"%10s %10s %10s %4s %10s %10s %4s %s\n","size","allocs", "bytes","(%)","frees","kept","(%)","    types");
  write(MPROF_OUTPUT_FILE,buffer,strlen(buffer));

  struct_list = malloc(1);
  struct_list[0] = 0;
  struct_list_length = 0;
  
  RB_FOREACH(memory_breakdown,MemoryBreakdownTree,&MEMORY_BREAKDOWNS)
  {
    i = 0;
    
    while(strlen(LIBMPROF_SHARED_MEM->libraries[i].name))
    {
      if(LIBMPROF_SHARED_MEM->libraries[i].dwarf && strcmp(LIBMPROF_SHARED_MEM->libraries[i].name,"libmprof.so"))
      {
        LIST_FOREACH(compilation_unit,&LIBMPROF_SHARED_MEM->libraries[i].dwarf->compilation_units,linkage)
        {
          RB_FOREACH(struct_,DwarfyStructTree,&compilation_unit->structs)
          {
            if(struct_->size == memory_breakdown->size)
            {
              if(struct_list_length > 0)
                strcat(struct_list,", ");
              
              if(strlen(struct_list) + strlen(struct_->name) + 3 > struct_list_length)
              {
                struct_list = realloc(struct_list,struct_list_length + 256);
                struct_list_length += 256;
              }
              strcat(struct_list,struct_->name);
            }
          }
        }
      }
      i++;
    }
    
    sprintf(buffer,"%10lu %10lu %10lu %4s %10lu %10lu %4s     %s\n",
    memory_breakdown->size,
    memory_breakdown->total_num_allocs,
    memory_breakdown->total_bytes_allocated,
    percentage_as_string(memory_breakdown->total_bytes_allocated,LIBMPROF_TOTAL_BYTES_ALLOCATED,percentage1_buff),
    memory_breakdown->total_num_frees,
    memory_breakdown->current_bytes_allocated,
    percentage_as_string(memory_breakdown->total_bytes_allocated,LIBMPROF_TOTAL_BYTES_ALLOCATED - LIBMPROF_TOTAL_BYTES_FREED,percentage2_buff),
    struct_list);
    write(MPROF_OUTPUT_FILE,buffer,strlen(buffer));
    struct_list = realloc(struct_list,1);
    struct_list[0] = 0;
    struct_list_length = 0;
  }
  
  sprintf(buffer,"\n");
  write(MPROF_OUTPUT_FILE,buffer,strlen(buffer));
}

void function_breakdown_table_out()
{
  FunctionBreakdown *function_breakdown;
  char buffer[512];
  char percentage1_buff[4];
  char percentage2_buff[4];
  char percentage3_buff[4];
  char percentage4_buff[4];
  char alloc_size_breakdown[32];
  char leak_size_breakdown[32];
  
  sprintf(buffer,"[mprof] TABLE 3: DIRECT_ALLOCATION\n\n");
  write(MPROF_OUTPUT_FILE,buffer,strlen(buffer));
  
  sprintf(buffer,"%12s %12s %16s %12s %16s %12s %s\n","% mem","bytes","% mem(size)","bytes kept","% all kept","calls","    name");
  write(MPROF_OUTPUT_FILE,buffer,strlen(buffer));
  
  sprintf(buffer,"                             s   m   l   x                 s   m   l   x\n");
  write(MPROF_OUTPUT_FILE,buffer,strlen(buffer));
  
  RB_FOREACH(function_breakdown,FunctionBreakdownTree,&FUNCTION_BREAKDOWNS)
  {

    sprintf(alloc_size_breakdown,"%4s%4s%4s%4s",
            percentage_as_string(function_breakdown->num_allocations_small,LIBMPROF_NUM_ALLOCATIONS_SMALL,percentage1_buff),
            percentage_as_string(function_breakdown->num_allocations_medium,LIBMPROF_NUM_ALLOCATIONS_MEDIUM,percentage2_buff),
            percentage_as_string(function_breakdown->num_allocations_large,LIBMPROF_NUM_ALLOCATIONS_LARGE,percentage3_buff),
            percentage_as_string(function_breakdown->num_allocations_xlarge,LIBMPROF_NUM_ALLOCATIONS_XLARGE,percentage4_buff));
    
    sprintf(leak_size_breakdown,"%4s%4s%4s%4s",
            percentage_as_string(function_breakdown->current_small_bytes_allocated,LIBMPROF_TOTAL_BYTES_ALLOCATED - LIBMPROF_TOTAL_BYTES_FREED,percentage1_buff),
            percentage_as_string(function_breakdown->current_medium_bytes_allocated,LIBMPROF_TOTAL_BYTES_ALLOCATED - LIBMPROF_TOTAL_BYTES_FREED,percentage2_buff),
            percentage_as_string(function_breakdown->current_large_bytes_allocated,LIBMPROF_TOTAL_BYTES_ALLOCATED - LIBMPROF_TOTAL_BYTES_FREED,percentage3_buff),
            percentage_as_string(function_breakdown->current_xlarge_bytes_allocated,LIBMPROF_TOTAL_BYTES_ALLOCATED - LIBMPROF_TOTAL_BYTES_FREED,percentage4_buff));
    
    sprintf(buffer,"%12s %12lu %16s %12lu %16s %12lu     %s()\n",
    percentage_as_string(function_breakdown->total_bytes_allocated,LIBMPROF_TOTAL_BYTES_ALLOCATED,percentage1_buff),
    function_breakdown->total_bytes_allocated,
    alloc_size_breakdown,
    function_breakdown->current_bytes_allocated,
    leak_size_breakdown,
    function_breakdown->num_calls,
    function_breakdown->name);
    write(MPROF_OUTPUT_FILE,buffer,strlen(buffer));
  }
  sprintf(buffer,"\n");
  write(MPROF_OUTPUT_FILE,buffer,strlen(buffer));
}

void leak_table_out()
{
  TransactionPoint *transaction_point;
  TransactionPath *transaction_path;
  TransactionPathSorted *transaction_path_sorted;
  char buffer[512];
  char percentage1_buff[4];
  char percentage2_buff[4];
  char percentage3_buff[4];

  TransactionPathSortedTree_t sorted_alloc_tree;
  TransactionPathSortedTree_t sorted_free_tree;
  TransactionPathSortedTree_t sorted_generic_tree;
  TransactionPathSorted *sorted;

  sprintf(buffer,"[mprof] TABLE 2: MEMORY LEAKS\n\n");
  write(MPROF_OUTPUT_FILE,buffer,strlen(buffer));
  
  sprintf(buffer,"%10s %4s%10s%10s %4s%10s%10s %4s     %s\n","kept bytes", "(%)","allocs", "bytes", "(%)","frees", "bytes", "(%)", "path");
  write(MPROF_OUTPUT_FILE,buffer,strlen(buffer));
  
    RB_INIT(&sorted_generic_tree);
    
    RB_FOREACH(transaction_point,TransactionPointTree,&TRANSACTION_POINTS)
    {
      RB_FOREACH(transaction_path,TransactionPathTree,&transaction_point->paths)
      {
        if(transaction_path->current_bytes_allocated || (LIBMPROF_SHARED_MEM->config.call_sites && transaction_path->total_bytes_freed))
        {
          sorted = malloc(sizeof(TransactionPathSorted));
          memcpy(sorted,transaction_path,sizeof(TransactionPath));
          RB_INSERT(TransactionPathSortedTree,&sorted_generic_tree,sorted);
        }
      }
    }
    
    RB_FOREACH(transaction_path_sorted,TransactionPathSortedTree,&sorted_generic_tree)
    {
      sprintf(buffer,"%10lu %4s%10lu%10lu %4s%10lu%10lu %4s     %s\n",
      transaction_path_sorted->current_bytes_allocated,
      percentage_as_string(transaction_path_sorted->current_bytes_allocated,LIBMPROF_TOTAL_BYTES_ALLOCATED - LIBMPROF_TOTAL_BYTES_FREED,percentage1_buff),

      transaction_path_sorted->total_num_transactions,
      transaction_path_sorted->total_bytes_allocated,

      percentage_as_string(transaction_path_sorted->total_bytes_allocated,LIBMPROF_TOTAL_BYTES_ALLOCATED,percentage2_buff),

      transaction_path_sorted->total_num_frees,
      transaction_path_sorted->total_bytes_freed,

      percentage_as_string(transaction_path_sorted->total_bytes_freed,LIBMPROF_TOTAL_BYTES_FREED,percentage3_buff),

      transaction_path_sorted->name);    
      write(MPROF_OUTPUT_FILE,buffer,strlen(buffer));
  }
  sprintf(buffer,"\n");
  write(MPROF_OUTPUT_FILE,buffer,strlen(buffer));
}

