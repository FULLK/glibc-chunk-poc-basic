#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

int main()
{
    size_t* chunk1=malloc(0x10);
    free(chunk1);
    free(chunk1);
    size_t* chunk2=malloc(0x10);
    size_t fakechunk[0x20];
    chunk2[0]=fakechunk;
    malloc(0x10);
    size_t* destchunk=malloc(0x10);
    printf("destchunk 0x%p\n",destchunk);
    printf("fakechunk 0x%p\n",fakechunk);

}