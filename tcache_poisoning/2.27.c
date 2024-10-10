#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

int main()
{
    size_t* chunk1=malloc(0x10);
    free(chunk1);
    size_t fakechunk[0x20];
    chunk1[0]=fakechunk;  //memory
    malloc(0x10);
    size_t* destchunk=malloc(0x10);
    printf("destchunk 0x%p\n",destchunk);
    printf("&fakechunk[0] 0x%p\n",fakechunk);

}