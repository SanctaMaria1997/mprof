#include <stdlib.h>
#include <stdio.h>

struct leaky_struct
{
  int field1,field2;
};

struct other_leaky_struct
{
  short field1,field2,field3,field4;
};

struct large_leaky_struct
{
  char field[256];  
};

void leak_pls(int n); /* function leaks n bytes */
void leak_pls_too(int n); /* function also leaks n bytes */
void hamster(void); /* leaky function in another compilation unit */
void dugong(void); /* leaky function in another shared object */

int main(int argc,char **argv)
{
  char buff[16];
  int i,*p;
  
  struct leaky_struct *ls;
  struct other_leaky_struct *ols;
  struct large_leaky_struct *lls;
  
  /* allocate and leak some structs */
  
  ls = malloc(sizeof(struct leaky_struct));
  ols = malloc(sizeof(struct other_leaky_struct));
  lls = malloc(sizeof(struct large_leaky_struct));
  
  /* allocate 3 blocks, leaking the first 2 */
  
  for(i = 0; i < 3; i++)
    p = malloc(5);
  
  /* reallocate the third block with a new size */

  for(i = 1; i < 2; i++)
    p = realloc(p,20 * i);

  /* solicit some user input to confirm we can debug interactive programs */
  
  puts("Type something...");
  scanf("%s",buff);
  printf("I scanned '%s'!\n",buff);
  puts("Type something else...");
  scanf("%s",buff);
  printf("Then I scanned '%s'!\n",buff);
  
  /* call some leaky functions elsewhere */
  
  dugong();
  hamster();
  
  /* allocate, leak, and free */

  for(i = 0; i < 2; i++)
    p = malloc(6);
  
  free(p);

  for(i = 0; i < 5; i++)
  {
    puts("Love always gets in the way.");
  }
  
  /* request some bespoke leaks */
  
  leak_pls(101);
  leak_pls_too(99);
  
  /* try out calloc, and another leak */
  
  p = calloc(3,333);
  p = malloc(444);
  
  return 14; /* so long */
}

void leak_pls(int i)
{
  void *p;
  puts("Hi from leak_pls!");
  p = malloc(i);
}

void leak_pls_too(int i)
{
  void *p;
  puts("Hi from leak_pls_too!");
  p = malloc(i);
}

