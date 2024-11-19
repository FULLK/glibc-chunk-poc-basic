#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void getshell()
{
  system("/bin/sh");
}
//gcc -z norelro -static  -pie 2.35.c -g -o 2.35
// int main() {

//   char* leak_pie=getshell;
//   printf("leak pie %p\n",leak_pie);
//   char* fini_array=0xbc37b+leak_pie;
//   *(unsigned long long*)fini_array=getshell;
//   *(unsigned long long*)(fini_array+8)=getshell;
//   return 0;
// }

//gcc -z norelro   2.35.c -g -o 2.35

int main() {

  char* leak_pie=getshell;
  printf("leak pie %p\n",leak_pie);
  char* fini_array=0x202f+leak_pie;
  *(unsigned long long*)fini_array=getshell;

  return 0;
}