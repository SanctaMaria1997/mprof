#include <stdlib.h>
#include <stdio.h>

void indirect_leak1(int n);
void indirect_leak2(int n);
void actual_leak(int n);
void a_5019()
{
  malloc(5019);
}

int main(int argc,char **argv)
{
  a_5019();
  for(int k = 0; k < 5; k++)
  malloc(10);
  for(int k = 0; k < 20; k++)
  malloc(40);
  for(int k = 0; k < 4; k++)
  malloc(300);
  exit(0);
  puts("Hi from test");
  indirect_leak1(123);
  puts("Hi again from test");
  indirect_leak2(321);
  char buff[32];
  scanf("%s",buff);
  int *p = malloc(20);
  free(p);
  p = calloc(3,40);
  //free(p);
  return 0;
}

void indirect_leak1(int n)
{
  actual_leak(n);
}

void indirect_leak2(int n)
{
  actual_leak(n);
}

void actual_leak(int n)
{
  void *p;
  p = malloc(n);
  if(n == 123)
    free(p);
}
