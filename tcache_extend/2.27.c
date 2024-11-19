#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
int main()
{   
    size_t* chunk1=malloc(0x20);
    size_t* chunk2=malloc(0x20);
    size_t* chunk3=malloc(0x20);
    chunk1[-1]=0x90;
    free(chunk1);
    size_t* extent_chunk=malloc(0x80);
    printf("extent_chunk size %p\n",chunk1[-1]);
    printf("chunk2 size %p\n",chunk1[5]);
    printf("chunk3 size %p\n",chunk1[11]);
}