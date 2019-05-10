# mprof
C Memory Profiler

mprof is a rewrite of a classic Unix tool which analyses a C program's memory usage and prints 
out several detailed reports.

- Find memory leaks
- Quickly see which C files were responsible for leaks (including exact line numbers)
- Find out which functions (or chains of functions) are allocating/freeing/leaking the most 
memory (in terms 
of both function calls and bytes)
- Get a breakdown of memory chunk sizes to understand how your program uses memory
- Find out which C structs in your source code correspond to the memory your program allocates

To build and install:

`make`
`sudo make install`
