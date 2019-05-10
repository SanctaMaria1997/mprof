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

#ifndef LIBMPROF_H
#define LIBMPROF_H

#ifdef LINUX
#include "tree.h"
#elif defined(FREEBSD)
#include <sys/tree.h>
#endif

#define MPROF_TRACE_DEPTH 5
#define TRANSACTION_TYPE_ALLOC 1
#define TRANSACTION_TYPE_FREE 2
#define TRANSACTION_TYPE_GENERIC 3

typedef RB_HEAD(TransactionPointTree,TransactionPoint) TransactionPointTree_t;
typedef RB_HEAD(TransactionPathTree,TransactionPath) TransactionPathTree_t;
typedef RB_HEAD(TransactionPathSortedTree,TransactionPathSorted) TransactionPathSortedTree_t;
typedef RB_HEAD(MemoryBlockTree,MemoryBlock) MemoryBlockTree_t;
typedef RB_HEAD(MemoryBlockSortedTree,MemoryBlockSorted) MemoryBlockSortedTree_t;
typedef RB_HEAD(MemoryBreakdownTree,MemoryBreakdown) MemoryBreakdownTree_t;
typedef RB_HEAD(FunctionBreakdownTree,FunctionBreakdown) FunctionBreakdownTree_t;

typedef struct TransactionPoint TransactionPoint;

struct TransactionPoint
{
  int transaction_type;
  long int address;
  TransactionPathTree_t paths;
  RB_ENTRY(TransactionPoint) TransactionPointLinks;
};

int compare_transaction_points(TransactionPoint *a1,TransactionPoint *a2);

RB_PROTOTYPE(TransactionPointTree,TransactionPoint,TransactionPointLinks,compare_transaction_points_by_address);

typedef struct TransactionPath TransactionPath;
typedef struct TransactionPathSorted TransactionPathSorted;

struct AllocationPath
{
  unsigned long int current_num_transactions;
  unsigned long int current_bytes_allocated;
  unsigned long int total_num_transactions;
  unsigned long int total_bytes_allocated;
  MemoryBlockTree_t memory_blocks;
};

struct FreePath
{
  unsigned long int total_num_frees;
  unsigned long int total_bytes_freed;
};

struct GenericPath
{
  unsigned long int current_num_transactions;
  unsigned long int current_bytes_allocated;
  unsigned long int total_num_transactions;
  unsigned long int total_bytes_allocated;
  unsigned long int total_num_frees;
  unsigned long int total_bytes_freed;
  MemoryBlockTree_t memory_blocks;
};

#define TRANSACTION_PATH(FFS)\
struct FFS\
{\
  char *name;\
  TransactionPoint *transaction_point;\
  unsigned long int current_num_transactions;\
  unsigned long int current_bytes_allocated;\
  unsigned long int total_num_transactions;\
  unsigned long int total_bytes_allocated;\
  unsigned long int total_num_frees;\
  unsigned long int total_bytes_freed;\
  MemoryBlockTree_t memory_blocks;\
  RB_ENTRY(FFS) FFS ## Links;\
};

TRANSACTION_PATH(TransactionPath);
TRANSACTION_PATH(TransactionPathSorted);

int compare_transaction_paths_by_name(TransactionPath *a1,TransactionPath *a2);
int compare_transaction_paths_by_leaked_bytes(TransactionPathSorted *a1,TransactionPathSorted *a2);

RB_PROTOTYPE(TransactionPathSortedTree,TransactionPathSorted,TransactionPathSortedLinks,compare_transaction_paths_by_name);
RB_PROTOTYPE(TransactionPathSortedTree,TransactionPathSorted,TransactionPathSortedLinks,compare_transaction_paths_by_leaked_bytes);

typedef struct MemoryBlock MemoryBlock;
typedef struct MemoryBlockSorted MemoryBlockSorted;

#define MEMORY_BLOCK(FFS)\
struct FFS\
{\
  unsigned long int address;\
  size_t size;\
  TransactionPath *path;\
  RB_ENTRY(FFS) FFS ## Links;\
};

MEMORY_BLOCK(MemoryBlock)
MEMORY_BLOCK(MemoryBlockSorted)

int compare_memory_blocks_by_address(MemoryBlock *mb1,MemoryBlock *mb2);
int compare_memory_blocks_by_size(MemoryBlockSorted *mb1,MemoryBlockSorted *mb2);

RB_PROTOTYPE(MemoryBlockTree,MemoryBlock,MemoryBlockLinks,compare_memory_blocks_by_address);
RB_PROTOTYPE(MemoryBlockSortedTree,MemoryBlockSorted,MemoryBlockSortedLinks,compare_memory_blocks_by_size);

typedef struct MemoryBreakdown MemoryBreakdown;

struct MemoryBreakdown
{
  size_t size;
  unsigned long int total_num_allocs;
  unsigned long int total_bytes_allocated;
  unsigned long int total_num_frees;
  unsigned long int current_bytes_allocated;
  RB_ENTRY(MemoryBreakdown) MemoryBreakdownLinks;
};

int compare_memory_breakdowns(MemoryBreakdown *mb1,MemoryBreakdown *mb2);

RB_PROTOTYPE(MemoryBreakdownTree,MemoryBreakdown,MemoryBreakdownLinks,compare_memory_breakdowns);

typedef struct FunctionBreakdown FunctionBreakdown;

struct FunctionBreakdown
{
  char *name;
  unsigned long int total_bytes_allocated;
  unsigned long int current_bytes_allocated;
  unsigned long int total_small_bytes_allocated;
  unsigned long int total_medium_bytes_allocated;
  unsigned long int total_large_bytes_allocated;
  unsigned long int total_xlarge_bytes_allocated;
  unsigned long int current_small_bytes_allocated;
  unsigned long int current_medium_bytes_allocated;
  unsigned long int current_large_bytes_allocated;
  unsigned long int current_xlarge_bytes_allocated;

  unsigned long int num_allocations_small;
  unsigned long int num_allocations_medium;
  unsigned long int num_allocations_large;
  unsigned long int num_allocations_xlarge;
  unsigned long int num_calls;
  RB_ENTRY(FunctionBreakdown) FunctionBreakdownLinks;
};

int compare_function_breakdowns(FunctionBreakdown *fb1,FunctionBreakdown *fb2);

RB_PROTOTYPE(FunctionBreakdownTree,FunctionBreakdown,FunctionBreakdownLinks,compare_function_breakdowns);

void memory_breakdown_table_out();
void leak_table_out();
void function_breakdown_table_out();

#endif
