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
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "dwarfy.h"
#include "mprof.h"
#include "libmprof.h"
#include "mprof_util.h"

RB_GENERATE(TransactionPointTree,TransactionPoint,TransactionPointLinks,compare_transaction_points);
RB_GENERATE(TransactionPathTree,TransactionPath,TransactionPathLinks,compare_transaction_paths_by_trace);
RB_GENERATE(TransactionPathSortedTree,TransactionPathSorted,TransactionPathSortedLinks,compare_transaction_paths_by_leaked_bytes);
RB_GENERATE(MemoryBlockTree,MemoryBlock,MemoryBlockLinks,compare_memory_blocks_by_address);
RB_GENERATE(MemoryBlockSortedTree,MemoryBlockSorted,MemoryBlockSortedLinks,compare_memory_blocks_by_size);
RB_GENERATE(MemoryBreakdownTree,MemoryBreakdown,MemoryBreakdownLinks,compare_memory_breakdowns);
RB_GENERATE(FunctionBreakdownTree,FunctionBreakdown,FunctionBreakdownLinks,compare_function_breakdowns);
RB_GENERATE(SortedLibraryTree,SortedLibrary,SortedLibraryLinks,compare_sorted_libraries);

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

FILE *MPROF_OUTPUT_FILE;
char MPROF_OUTPUT_FILE_NAME[256];

sem_t *MPROF_INSTANCE;
sem_t *MPROF_MEM_MUTEX;
char MPROF_MEM_MUTEX_NAME[256];
  
LibmprofSharedMem *LIBMPROF_SHARED_MEM;
int SHMID;
long int LIBMPROF_REGION_BASE[LIBMPROF_MAX_NUM_REGIONS];
long int LIBMPROF_NUM_REGIONS;

SortedLibraryTree_t LIBMPROF_LIBS;
TransactionPointTree_t TRANSACTION_POINTS;
MemoryBreakdownTree_t MEMORY_BREAKDOWNS;
FunctionBreakdownTree_t FUNCTION_BREAKDOWNS;

DWARF_DATAList_t DWARFY_PROGRAM;

void leak_report(void);

int compare_transaction_points(TransactionPoint *a1,TransactionPoint *a2)
{
  return a1->address - a2->address;
}

int compare_transaction_paths_by_trace(TransactionPath *a1,TransactionPath *a2)
{
  int i;
  int order;
  
  for(i = 0; i < MPROF_TRACE_DEPTH; i++)
  {
    order = strcmp(a1->trace->function_names[i],a2->trace->function_names[i]);
    {
      if(order < 0)
        return -1;
      else if(order > 0)
        return 1;
    }
  }
  return 0;
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

int compare_sorted_libraries(SortedLibrary *sl1,SortedLibrary *sl2)
{
  return strcmp(sl1->name,sl2->name);
}

SortedLibrary *copy_library(Library *lib)
{
  SortedLibrary *result = malloc(sizeof(SortedLibrary));
  memset(result,0,sizeof(SortedLibrary));
  strcpy(result->name,lib->name);
  result->dwarf = lib->dwarf;
  result->base_address = lib->base_address;
  return result;
}

void  __attribute__((constructor)) libmprof_init()
{
  int i = 0,j = 0,m = 0;
  int proj;
  int instance;
  char name[256];
  SortedLibrary *sorted_library;
  
  LIBMPROF_NUM_MALLOCS = LIBMPROF_NUM_CALLOCS = LIBMPROF_NUM_REALLOCS = LIBMPROF_NUM_FREES = 0;
  
  LIBMPROF_NUM_ALLOCATIONS_SMALL = LIBMPROF_NUM_ALLOCATIONS_MEDIUM = LIBMPROF_NUM_ALLOCATIONS_LARGE = LIBMPROF_NUM_ALLOCATIONS_XLARGE = LIBMPROF_NUM_FREES_SMALL = LIBMPROF_NUM_FREES_MEDIUM = LIBMPROF_NUM_FREES_LARGE = LIBMPROF_NUM_FREES_XLARGE = 0;
  
  LIBMPROF_TOTAL_NUM_BYTES_SMALL = LIBMPROF_TOTAL_NUM_BYTES_MEDIUM = LIBMPROF_TOTAL_NUM_BYTES_LARGE = LIBMPROF_TOTAL_NUM_BYTES_XLARGE = 0;
  
  LIBMPROF_CURRENT_NUM_BYTES_SMALL = LIBMPROF_CURRENT_NUM_BYTES_MEDIUM = LIBMPROF_CURRENT_NUM_BYTES_LARGE = LIBMPROF_CURRENT_NUM_BYTES_XLARGE = 0;
  
  LIBMPROF_TOTAL_NUM_TRANSACTIONS = 0;
  LIBMPROF_TOTAL_BYTES_ALLOCATED = 0;
  
  RB_INIT(&TRANSACTION_POINTS);
  RB_INIT(&MEMORY_BREAKDOWNS);
  RB_INIT(&FUNCTION_BREAKDOWNS);
  RB_INIT(&LIBMPROF_LIBS);
  
  MPROF_INSTANCE = sem_open("/mprof_instance",O_CREAT,0666,0);
  sem_getvalue(MPROF_INSTANCE,&instance);
  sprintf(MPROF_MEM_MUTEX_NAME,"/mprof_mem_mutex.%d",instance);
  MPROF_MEM_MUTEX = sem_open(MPROF_MEM_MUTEX_NAME,O_CREAT,0666,1);
  sprintf(MPROF_OUTPUT_FILE_NAME,"tables.mprof.%d",instance);
  SHMID = shmget(ftok(MPROF_OUTPUT_FILE_NAME,1),sizeof(LibmprofSharedMem),0666);
  LIBMPROF_SHARED_MEM = shmat(SHMID,0,0);
  
  if(LIBMPROF_SHARED_MEM->config.output_to_stderr)
    MPROF_OUTPUT_FILE = stderr;
  else
    MPROF_OUTPUT_FILE = fopen(MPROF_OUTPUT_FILE_NAME,"w");
  
  sem_post(MPROF_INSTANCE);
  
  raise(SIGTRAP);  
  
  while(strlen(LIBMPROF_SHARED_MEM->libraries[i].name))
  {
    if(LIBMPROF_SHARED_MEM->libraries[i].name[0] != '/')
    {
      strcpy(name,file_part(LIBMPROF_SHARED_MEM->libraries[i].name));
      if(0 == strcmp(name,"libmprof.so"))
      {
        LIBMPROF_SHARED_MEM->libraries[i].dwarf = load_dwarf("/usr/local/lib/libmprof.so",LIBMPROF_SHARED_MEM->libraries[i].base_address);
      }
      else if(strlen(find_file(name,".")))
      {
        LIBMPROF_SHARED_MEM->libraries[i].dwarf = load_dwarf(find_file(name,"."),LIBMPROF_SHARED_MEM->libraries[i].base_address);
        if(LIBMPROF_SHARED_MEM->libraries[i].dwarf == 0)
        {
          fprintf(stderr,"[mprof] Unable to load DWARF debug information from object \"%s\". Consider recompiling with -g to generate debug information.",LIBMPROF_SHARED_MEM->libraries[i].name);
          exit(1);
        }
      }
      sorted_library = copy_library(&LIBMPROF_SHARED_MEM->libraries[i]);
      RB_INSERT(SortedLibraryTree,&LIBMPROF_LIBS,sorted_library);
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
      {
        
        if(compilation_unit->has_main_function)
        {
          m = 1;
          goto exit;
        }
      }
    }
    i++;
  }
  
  exit:
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

TransactionPath *create_transaction_path(int transaction_type,Backtrace *trace,TransactionPoint *transaction_point)
{
  TransactionPath *transaction_path;
  
  transaction_path = malloc(sizeof(TransactionPath));
  memset(transaction_path,0,sizeof(TransactionPath));
  transaction_path->transaction_point = transaction_point;
  transaction_path->trace = malloc(sizeof(Backtrace));
  memcpy(transaction_path->trace,trace,sizeof(Backtrace));
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

Backtrace *create_backtrace()
{
  Backtrace *backtrace = malloc(sizeof(Backtrace));
  memset(backtrace,0,sizeof(Backtrace));
  return backtrace;
}

void trace_(unsigned long int *frame_pointer,Backtrace *trace,int depth)
{
  DwarfyFunction *function;
  DwarfyCompilationUnit *compilation_unit;
  DwarfySourceRecord *source_record;
  unsigned long int address;
  char location[256];
  char best_symbolic_name[256];
  char tmp[5];
  char *elipsis = "...";  
  Dl_info info;

  address = *(frame_pointer + 1);
  
  if(0 == dladdr((void*)address,&info))
  {
    puts("[mprof] Invalid frame pointer detected; consider recompiling this program without optimisations.");
    exit(1);
  }
  
  compilation_unit = address_to_compilation_unit(address);
  function = address_to_function(address,compilation_unit);
  source_record = address_to_source_record(address,compilation_unit);
  
  if(function)
  {
    strcpy(best_symbolic_name,function->name);
  }
  else
  {
    strcpy(best_symbolic_name,"?@");
    strcat(best_symbolic_name,file_part(info.dli_fname));
  }
  
  strcat(best_symbolic_name,"()");
  
  if(LIBMPROF_SHARED_MEM->config.call_sites && compilation_unit)
  {
    sprintf(location," [%s:%d] ",compilation_unit->file_names[source_record->file - 1],source_record->line_number);
  }
  else
    sprintf(location,"");
  
  strcpy(trace->function_names[depth],best_symbolic_name);
  strcat(trace->function_names[depth],location);
  strcpy(tmp,best_symbolic_name);
  tmp[4] = 0;
  if(strcmp(tmp,"main"))
  {
    if(depth == MPROF_TRACE_DEPTH - 1)
      trace->too_deep = 1;
    else if(function)
      trace_((unsigned long int*)*frame_pointer,trace,depth + 1);
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

void update_memory_breakdowns_with_free(MemoryBlock *memory_block)
{
  MemoryBreakdown *memory_breakdown;
  MemoryBreakdown match_memory_breakdown;
  
  match_memory_breakdown.size = memory_block->size;
    
  if(0 == (memory_breakdown = RB_FIND(MemoryBreakdownTree,&MEMORY_BREAKDOWNS,&match_memory_breakdown)))
  {
    memory_breakdown = malloc(sizeof(MemoryBreakdown));
    memset(memory_breakdown,0,sizeof(MemoryBreakdown));
    memory_breakdown->size = memory_block->size;
  }
  
  memory_breakdown->current_bytes_allocated -= memory_block->size;
  memory_breakdown->total_num_frees++;

}

void update_function_breakdowns_with_alloc(unsigned long int *frame_pointer,size_t size)
{
  DwarfyFunction *function;
  unsigned long int address;
  FunctionBreakdown *function_breakdown;
  FunctionBreakdown match_function_breakdown;
  DwarfyCompilationUnit *compilation_unit;

  address = *(frame_pointer + 1);
  compilation_unit = address_to_compilation_unit(address);
  function = address_to_function(address,compilation_unit);
  if(function == 0)
    return;

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
    function_breakdown->num_allocations_small++;
  else if(size <= 256)
    function_breakdown->num_allocations_medium++;
  else if(size <= 2048)
    function_breakdown->num_allocations_large++;
  else
    function_breakdown->num_allocations_xlarge++;
}

void update_function_breakdowns_with_free(unsigned long int *frame_pointer,MemoryBlock *memory_block)
{
  DwarfyFunction *orig_function, *curr_function;
  DwarfyCompilationUnit *compilation_unit;
  unsigned long int address;
  FunctionBreakdown *curr_function_breakdown, *orig_function_breakdown;
  FunctionBreakdown match_function_breakdown;
  unsigned long int curr_address,orig_address;
  
  curr_address = *(frame_pointer + 1);
  compilation_unit = address_to_compilation_unit(curr_address);
  curr_function = address_to_function(curr_address,compilation_unit);
  
  orig_address = memory_block->path->transaction_point->address + 1;
  compilation_unit = address_to_compilation_unit(orig_address);
  orig_function = address_to_function(orig_address,compilation_unit);
  
  if(curr_function == 0 || orig_function == 0)
    return; 
  
  match_function_breakdown.name = curr_function->name;
  
  if(0 == (curr_function_breakdown = RB_FIND(FunctionBreakdownTree,&FUNCTION_BREAKDOWNS,&match_function_breakdown)))
  {
    curr_function_breakdown = malloc(sizeof(FunctionBreakdown));
    memset(curr_function_breakdown,0,sizeof(FunctionBreakdown));
    curr_function_breakdown->name = malloc(strlen(curr_function->name) + 1);
    strcpy(curr_function_breakdown->name,curr_function->name);
    RB_INSERT(FunctionBreakdownTree,&FUNCTION_BREAKDOWNS,curr_function_breakdown);
  }

  match_function_breakdown.name = orig_function->name;
  
  if(0 == (orig_function_breakdown = RB_FIND(FunctionBreakdownTree,&FUNCTION_BREAKDOWNS,&match_function_breakdown)))
  {
    orig_function_breakdown = malloc(sizeof(FunctionBreakdown));
    memset(orig_function_breakdown,0,sizeof(FunctionBreakdown));
    orig_function_breakdown->name = malloc(strlen(orig_function->name) + 1);
    strcpy(orig_function_breakdown->name,orig_function->name);
    RB_INSERT(FunctionBreakdownTree,&FUNCTION_BREAKDOWNS,orig_function_breakdown);
  }
  
  curr_function_breakdown->num_calls++;
  if(memory_block->size > orig_function_breakdown->current_bytes_allocated)
    orig_function_breakdown->current_bytes_allocated = 0; // prevent integer wrap around due to invalid frees
  else
    orig_function_breakdown->current_bytes_allocated -= memory_block->size;

  if(memory_block->size <= 32)
    orig_function_breakdown->num_frees_small++;
  else if(memory_block->size <= 256)
    orig_function_breakdown->num_frees_medium++;
  else if(memory_block->size <= 2048)
    orig_function_breakdown->num_frees_large++;
  else
    orig_function_breakdown->num_frees_xlarge++;
}

void *mprof_g_malloc(size_t size)
{
  return mprof_malloc(size);
}

void *mprof_g_malloc0(size_t size)
{
  return mprof_malloc(size);
}

void *mprof_g_malloc_n(size_t num,size_t size)
{
  return mprof_calloc(num,size);
}

void *mprof_g_realloc(void *ptr,size_t size)
{
  return mprof_realloc(ptr,size);
}

void *mprof_g_realloc_n(void *ptr,size_t num,size_t size)
{
  return mprof_realloc(ptr,num * size);
}

void *mprof_g_try_malloc(size_t size)
{
  void *result;
  if(0 == (result = mprof_malloc(size)));
  {
    fprintf(stderr,"[mprof] g_try_malloc() failed (out of memory).");
    exit(1);
  }
  return result;
}

void *mprof_g_try_malloc0(size_t size)
{
  void *result;
  if(0 == (result = mprof_malloc(size)));
  {
    fprintf(stderr,"[mprof] mprof_g_try_malloc0() failed.");
    exit(1);
  }
  return result;
}

void *mprof_g_try_realloc(size_t size)
{
  void *result;
  if(0 == (result = mprof_malloc(size)));
  {
    fprintf(stderr,"[mprof] mprof_g_try_realloc() failed.");
    exit(1);
  }
  return result;
}

void *mprof_g_try_malloc_n(size_t num,size_t size)
{
  void *result;
  if(0 == (result = mprof_malloc(num * size)));
  {
    fprintf(stderr,"[mprof] mprof_g_try_malloc_n() failed.");
    exit(1);
  }
  return result;
}

void *mprof_g_try_malloc0_n(size_t num,size_t size)
{
  void *result;
  if(0 == (result = mprof_malloc(num * size)));
  {
    fprintf(stderr,"[mprof] mprof_g_try_malloc0_n() failed.");
    exit(1);
  }
  return result;
}

void *mprof_g_try_realloc_n(void *mem,size_t num,size_t size)
{
  void *result;
  if(0 == (result = mprof_realloc(mem,num * size)));
  {
    fprintf(stderr,"[mprof] mprof_g_try_realloc_n() failed.");
    exit(1);
  }
  return result;
}


void mprof_g_free(void *mem)
{
  mprof_free(mem);
}

void *mprof_malloc(size_t size)
{  
  sem_wait(MPROF_MEM_MUTEX);
  
  void *result;
  long int return_address = 0;
  long int transaction_address;
  Backtrace *trace;
  unsigned long int *frame_pointer;
  TransactionPoint match_transaction_point;
  TransactionPoint *transaction_point;
  TransactionPath match_transaction_path;
  TransactionPath *transaction_path;
  MemoryBlock *memory_block;
  DwarfyFunction *parent_function;
  DwarfyCompilationUnit *compilation_unit;

  __asm__
  (
    "movq %%rbp, %0\n"
    : [frame_pointer] "=r"(frame_pointer)
  );
  
  if(LIBMPROF_SHARED_MEM->config.gnu)
    frame_pointer = (unsigned long int*)(*frame_pointer);
  
  trace = create_backtrace();
  trace_(frame_pointer,trace,0);

  return_address = *(frame_pointer + 1);

  compilation_unit = address_to_compilation_unit(return_address);
  parent_function = address_to_function(return_address,compilation_unit);
  
  if(LIBMPROF_SHARED_MEM->config.call_sites || parent_function == 0)
    match_transaction_point.address = return_address;
  else
    match_transaction_point.address = parent_function->address;
  
  match_transaction_path.trace = trace;
  
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
  memset(result,0,size);
  
  memory_block = create_memory_block((unsigned long int)result,size,transaction_path);

  LIBMPROF_TOTAL_NUM_TRANSACTIONS++;
  LIBMPROF_NUM_MALLOCS++;
  LIBMPROF_TOTAL_BYTES_ALLOCATED += size;
  update_alloc_bins(size);
  update_memory_breakdowns_with_alloc(size);
  update_function_breakdowns_with_alloc(frame_pointer,size);
  free(trace);
  sem_post(MPROF_MEM_MUTEX);
  
  return result;
}

void *mprof_calloc(size_t num,size_t size)
{
  sem_wait(MPROF_MEM_MUTEX);
  void *result;
  long int return_address = 0;
  long int transaction_address;
  unsigned long int *frame_pointer;
  TransactionPoint match_transaction_point;
  TransactionPoint *transaction_point;
  TransactionPath match_transaction_path;
  TransactionPath *transaction_path;
  Backtrace *trace;
  MemoryBlock *memory_block;
  DwarfyFunction *parent_function;
  DwarfyCompilationUnit *compilation_unit;
  
  __asm__
  (
    "movq %%rbp, %0\n"
    : [frame_pointer] "=r"(frame_pointer)
  );
  
  if(LIBMPROF_SHARED_MEM->config.gnu)
    frame_pointer = (unsigned long int*)(*frame_pointer);

  trace = create_backtrace();
  trace_(frame_pointer,trace,0);

  return_address = *(frame_pointer + 1);
  
  compilation_unit = address_to_compilation_unit(return_address);
  parent_function = address_to_function(return_address,compilation_unit);

  if(LIBMPROF_SHARED_MEM->config.call_sites || parent_function == 0)
    match_transaction_point.address = return_address;
  else
    match_transaction_point.address = parent_function->address;

  match_transaction_path.trace = trace;
  
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
  memset(result,0,num * size);
  
  memory_block = create_memory_block((unsigned long int)result,num * size,transaction_path);

  LIBMPROF_TOTAL_NUM_TRANSACTIONS++;
  LIBMPROF_NUM_CALLOCS++;
  LIBMPROF_TOTAL_BYTES_ALLOCATED += num * size;
  update_alloc_bins(num * size);
  update_memory_breakdowns_with_alloc(num * size);
  update_function_breakdowns_with_alloc(frame_pointer,num * size);
free(trace);
  sem_post(MPROF_MEM_MUTEX);
  
  return result;
}

void *mprof_realloc(void *ptr,size_t size)
{
  sem_wait(MPROF_MEM_MUTEX);
  void *result;
  long int return_address = 0;
  long int size_difference = 0;
  unsigned long int *frame_pointer;
  Backtrace *trace;
  unsigned long int block_size_increase;
  TransactionPoint match_transaction_point;
  TransactionPoint *transaction_point;
  TransactionPath match_transaction_path;
  TransactionPath *transaction_path;
  MemoryBlock *memory_block,match_memory_block;
  DwarfyFunction *parent_function;
  DwarfyCompilationUnit *compilation_unit;
  
  match_memory_block.address = (unsigned long int)ptr;
  
  if(ptr == 0)
  {
    sem_post(MPROF_MEM_MUTEX);
    return mprof_malloc(size);
  }
  
  __asm__
  (
    "movq %%rbp, %0\n"
    : [frame_pointer] "=r"(frame_pointer)
  );
  
  if(LIBMPROF_SHARED_MEM->config.gnu)
    frame_pointer = (unsigned long int*)(*frame_pointer);

  trace = create_backtrace();
  trace_(frame_pointer,trace,0);

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
    return realloc(ptr,size);
  
  size_difference = ((long int)size) - ((long int)(memory_block->size));
  compilation_unit = address_to_compilation_unit(return_address);
  parent_function = address_to_function(return_address,compilation_unit);
  
  if(LIBMPROF_SHARED_MEM->config.call_sites || parent_function == 0)
    match_transaction_point.address = return_address;
  else
    match_transaction_point.address = parent_function->address;
  
  match_transaction_path.trace = trace;
  
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
  sem_post(MPROF_MEM_MUTEX);
  
  return result;
}

void mprof_free(void *ptr)
{
  sem_wait(MPROF_MEM_MUTEX);
  MemoryBlock match;
  MemoryBlock *memory_block;
  TransactionPoint *transaction_point;
  TransactionPath *transaction_path;
  TransactionPoint match_transaction_point;
  TransactionPath *orig_transaction_path;
  TransactionPoint *orig_transaction_point;
  TransactionPath match_transaction_path;
  DwarfyFunction *parent_function;
  DwarfyCompilationUnit *compilation_unit;
  long int return_address = 0;
  Backtrace *trace;
  unsigned long int *frame_pointer;
  
  __asm__
  (
    "movq %%rbp, %0\n"
    : [frame_pointer] "=r"(frame_pointer)
  );
  
  if(LIBMPROF_SHARED_MEM->config.gnu)
    frame_pointer = (unsigned long int*)(*frame_pointer);
  
  trace = create_backtrace();
  trace_(frame_pointer,trace,0);
  
  return_address = *(frame_pointer + 1);
  
  match_transaction_path.trace = trace;

  compilation_unit = address_to_compilation_unit(return_address);
  parent_function = address_to_function(return_address,compilation_unit);
  
  if(LIBMPROF_SHARED_MEM->config.call_sites || parent_function == 0)
    match_transaction_point.address = return_address;
  else
    match_transaction_point.address = parent_function->address;
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
        update_memory_breakdowns_with_free(memory_block);
        update_function_breakdowns_with_free(frame_pointer,memory_block);
        free(memory_block);
    
      }
    }
  }
  
  LIBMPROF_NUM_FREES++;

free(trace);
  free(ptr);
  sem_post(MPROF_MEM_MUTEX);
  
}

__attribute__((destructor)) void libmprof_final()
{
  fprintf(stderr,"\n[mprof] MEMORY STATISTICS\n");
  
  memory_breakdown_table_out();
  leak_table_out();
  function_breakdown_table_out();

  fprintf(stderr,"[mprof] Memory usage summary:\n");
  fprintf(stderr,"[mprof] Program allocated %ld block(s)\n",LIBMPROF_TOTAL_NUM_TRANSACTIONS);
  fprintf(stderr,"[mprof] (malloc: %ld, calloc: %ld, realloc: %ld)\n",LIBMPROF_NUM_MALLOCS,LIBMPROF_NUM_CALLOCS,LIBMPROF_NUM_REALLOCS);
  fprintf(stderr,"[mprof] Program freed %ld block(s)\n",LIBMPROF_NUM_FREES);
  if(0 == LIBMPROF_SHARED_MEM->config.output_to_stderr)
    fprintf(stderr,"[mprof] For detailed memory usage statistics, consult the file \"%s\".\n",MPROF_OUTPUT_FILE_NAME);

  shmdt(LIBMPROF_SHARED_MEM);
  sem_unlink(MPROF_MEM_MUTEX_NAME);
  fclose(MPROF_OUTPUT_FILE);
}

DwarfySourceRecord *address_to_source_record(unsigned long int address,DwarfyCompilationUnit  *compilation_unit)
{
  DwarfyObjectRecord match_location_record;
  DwarfyObjectRecord *object_record;
  DwarfySourceRecord *source_record;
  Dl_info info;
  
  if(compilation_unit == 0)
    return 0;
  
  match_location_record.address = address;
  
  match_location_record.address = address;
  object_record = RB_NFIND(DwarfyObjectRecordTree,&compilation_unit->line_numbers,&match_location_record);

  source_record = LIST_FIRST(&object_record->source_records);
  return source_record;
}

DwarfyFunction *address_to_function(unsigned long int address,DwarfyCompilationUnit *compilation_unit)
{
  DwarfyFunction *function;
  DwarfyFunction match_function;

  if(compilation_unit == 0)
    return 0;
  
  function = 0;
  
  match_function.address = address;
  function = RB_NFIND(DwarfyFunctionTree,&compilation_unit->functions,&match_function);

  return function;
}

void squash(char *st)
{
    int z = 0;
    while(st[z] != 0)
    {
      if(strlen(st + z) >= 3 && st[z] == '.' && st[z+1] == 's' && st[z+2] == 'o')
      {
        st[z+3] = 0;
        break;
      }
      z++;
    }
}

DwarfyCompilationUnit *address_to_compilation_unit(unsigned long int address)
{
  DwarfyObjectRecord match_location_record;
  DwarfyObjectRecord *nearest;
  DwarfyCompilationUnit *compilation_unit;
  DwarfyCompilationUnit *nearest_compilation_unit = 0;
  SortedLibrary match_library,*library;
  unsigned long int *nearest_address = (unsigned long int*)0xFFFFFFFFFFFFFFFF;
  Dl_info info;
  char buff[256];
  int i = 0;
  
  if(0 == dladdr((void*)address,&info))
    return 0;
  
  strcpy(buff,file_part(info.dli_fname));
  squash(buff);
  
  SortedLibrary *sl;
  strcpy(match_library.name,buff);
  
  if(0 == (sl = RB_FIND(SortedLibraryTree,&LIBMPROF_LIBS,&match_library)))
    return 0;

  if(sl->dwarf == 0)
    return 0;
  
  match_location_record.address = address;
  
  RB_FOREACH(library,SortedLibraryTree,&LIBMPROF_LIBS)
  {
    if(library->dwarf)
    {
      LIST_FOREACH(compilation_unit,&library->dwarf->compilation_units,linkage)
      {
        nearest = RB_NFIND(DwarfyObjectRecordTree,&compilation_unit->line_numbers,&match_location_record);

        if(nearest && ((void*)(address - nearest->address)) < ((void*)nearest_address))
        {
          nearest_address = ((void*)(address - nearest->address));
          nearest_compilation_unit = compilation_unit;
        }
      }
    }
  }
  
  
  return nearest_compilation_unit;
}

char *percentage_as_string(unsigned long int numerator,unsigned long int denominator,char *buffer)
{
  double percentage;
  
  if(denominator == 0)
  {
    strcpy(buffer,"0");
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
  char percentage1_buff[4];
  char percentage2_buff[4];
  char *struct_list;
  int struct_list_length;
  int i;
  
  fprintf(MPROF_OUTPUT_FILE,"[mprof] TABLE 1: ALLOCATION BINS\n\n");
  fprintf(MPROF_OUTPUT_FILE,"%10s %10s %10s %4s %10s %10s %4s %s\n","size","allocs", "bytes","(%)","frees","kept","(%)","    types");
 
  struct_list = malloc(1);
  struct_list[0] = 0;
  struct_list_length = 0;

  RB_FOREACH(memory_breakdown,MemoryBreakdownTree,&MEMORY_BREAKDOWNS)
  {
    i = 0;
    if(LIBMPROF_SHARED_MEM->config.structs)
    {    
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
    }
    fprintf(MPROF_OUTPUT_FILE,"%10lu %10lu %10lu %4s %10lu %10lu %4s     %s\n",
    memory_breakdown->size,
    memory_breakdown->total_num_allocs,
    memory_breakdown->total_bytes_allocated,
    percentage_as_string(memory_breakdown->total_bytes_allocated,LIBMPROF_TOTAL_BYTES_ALLOCATED,percentage1_buff),
    memory_breakdown->total_num_frees,
    memory_breakdown->current_bytes_allocated,
    percentage_as_string(memory_breakdown->total_bytes_allocated,LIBMPROF_TOTAL_BYTES_ALLOCATED - LIBMPROF_TOTAL_BYTES_FREED,percentage2_buff),
    struct_list);
    struct_list = realloc(struct_list,1);
    struct_list[0] = 0;
    struct_list_length = 0;
  }
  fprintf(MPROF_OUTPUT_FILE,"\n");
}

void function_breakdown_table_out()
{
  FunctionBreakdown *function_breakdown;
  char percentage1_buff[4];
  char percentage2_buff[4];
  char percentage3_buff[4];
  char percentage4_buff[4];
  char alloc_size_breakdown[32];
  char leak_size_breakdown[32];

  fprintf(MPROF_OUTPUT_FILE,"[mprof] TABLE 3: DIRECT_ALLOCATION\n\n");
  fprintf(MPROF_OUTPUT_FILE,"%12s %12s %16s %12s %16s %12s %s\n","% mem","bytes","% mem(size)","bytes kept","% all kept","calls","    name");
  fprintf(MPROF_OUTPUT_FILE,"                             s   m   l   x                 s   m   l   x\n");
  
  RB_FOREACH(function_breakdown,FunctionBreakdownTree,&FUNCTION_BREAKDOWNS)
  {
    sprintf(alloc_size_breakdown,"%4s%4s%4s%4s",
            percentage_as_string(function_breakdown->num_allocations_small,LIBMPROF_NUM_ALLOCATIONS_SMALL,percentage1_buff),
            percentage_as_string(function_breakdown->num_allocations_medium,LIBMPROF_NUM_ALLOCATIONS_MEDIUM,percentage2_buff),
            percentage_as_string(function_breakdown->num_allocations_large,LIBMPROF_NUM_ALLOCATIONS_LARGE,percentage3_buff),
            percentage_as_string(function_breakdown->num_allocations_xlarge,LIBMPROF_NUM_ALLOCATIONS_XLARGE,percentage4_buff));
    
    sprintf(leak_size_breakdown,"%4s%4s%4s%4s",
            percentage_as_string(function_breakdown->num_allocations_small - function_breakdown->num_frees_small,LIBMPROF_NUM_ALLOCATIONS_SMALL - LIBMPROF_NUM_FREES_SMALL,percentage1_buff),
            percentage_as_string(function_breakdown->num_allocations_medium - function_breakdown->num_frees_medium,LIBMPROF_NUM_ALLOCATIONS_MEDIUM - LIBMPROF_NUM_FREES_MEDIUM,percentage2_buff),
            percentage_as_string(function_breakdown->num_allocations_large - function_breakdown->num_frees_large,LIBMPROF_NUM_ALLOCATIONS_LARGE - LIBMPROF_NUM_FREES_LARGE,percentage3_buff),
            percentage_as_string(function_breakdown->num_allocations_xlarge - function_breakdown->num_frees_xlarge,LIBMPROF_NUM_ALLOCATIONS_XLARGE - LIBMPROF_NUM_FREES_XLARGE,percentage4_buff));

    fprintf(MPROF_OUTPUT_FILE,"%12s %12lu %16s %12lu %16s %12lu     %s()\n",
    percentage_as_string(function_breakdown->total_bytes_allocated,LIBMPROF_TOTAL_BYTES_ALLOCATED,percentage1_buff),
    function_breakdown->total_bytes_allocated,
    alloc_size_breakdown,
    function_breakdown->current_bytes_allocated,
    leak_size_breakdown,
    function_breakdown->num_calls,
    function_breakdown->name);
    
  }
  fprintf(MPROF_OUTPUT_FILE,"\n");
}

void leak_table_out()
{
  TransactionPoint *transaction_point;
  TransactionPath *transaction_path;
  TransactionPathSorted *transaction_path_sorted;
  char path[512];
  char percentage1_buff[4];
  char percentage2_buff[4];
  char percentage3_buff[4];
  int i;

  TransactionPathSortedTree_t sorted_alloc_tree;
  TransactionPathSortedTree_t sorted_free_tree;
  TransactionPathSortedTree_t sorted_generic_tree;
  TransactionPathSorted *sorted;

  fprintf(MPROF_OUTPUT_FILE,"[mprof] TABLE 2: MEMORY LEAKS\n\n");
  fprintf(MPROF_OUTPUT_FILE,"%10s %4s%10s%10s %4s%10s%10s %4s     %s\n","kept bytes", "(%)","allocs", "bytes", "(%)","frees", "bytes", "(%)", "path");
  
  
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

      path[0] = 0;
      
      if(transaction_path_sorted->trace->too_deep)
        strcat(path,"... ");
      
      for(i = MPROF_TRACE_DEPTH - 1; i >= 0; i--)
      {
        if(transaction_path_sorted->trace->function_names[i][0])
        {
          strcat(path,transaction_path_sorted->trace->function_names[i]);
          if(i)
            strcat(path," -> ");
        }
      }
      
      fprintf(MPROF_OUTPUT_FILE,"%10lu %4s%10lu%10lu %4s%10lu%10lu %4s     %s\n",
      transaction_path_sorted->current_bytes_allocated,
      percentage_as_string(transaction_path_sorted->current_bytes_allocated,LIBMPROF_TOTAL_BYTES_ALLOCATED - LIBMPROF_TOTAL_BYTES_FREED,percentage1_buff),

      transaction_path_sorted->total_num_transactions,
      transaction_path_sorted->total_bytes_allocated,

      percentage_as_string(transaction_path_sorted->total_bytes_allocated,LIBMPROF_TOTAL_BYTES_ALLOCATED,percentage2_buff),

      transaction_path_sorted->total_num_frees,
      transaction_path_sorted->total_bytes_freed,

      percentage_as_string(transaction_path_sorted->total_bytes_freed,LIBMPROF_TOTAL_BYTES_FREED,percentage3_buff),

      path);    
  }
  fprintf(MPROF_OUTPUT_FILE,"\n");
}
