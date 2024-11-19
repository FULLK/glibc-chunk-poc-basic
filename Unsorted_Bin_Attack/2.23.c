#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

int main()
{
    size_t* chunk1=malloc(0x410);
    size_t* fakechunk[0x20];
    malloc(0x10);
    free(chunk1);
    chunk1[1]=fakechunk;
    fakechunk[1]=0x20;
    size_t* chunk2=malloc(0x410);
    size_t* destchunk=malloc(0x10);
    //printf("destchunk %p",destchunk);
    // printf("malloc part fd %p bk %p\n",chunk2[0],chunk2[1]);
    
}