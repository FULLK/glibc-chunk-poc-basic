#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>


int main()
{
    size_t* chunk1=malloc(0x40);
    size_t* chunk2=malloc(0x40);
    chunk1[1]=0x30;   //  chunk is mmap and size align 0x10
    chunk1[7]=0x27; // in chunk range just ok
    free(&chunk1[2]);
    size_t* dest_chunk=malloc(0x20);
    printf("dest_chunk %p\n",dest_chunk);
    printf("&chunk1[2] %p\n",&chunk1[2]);
}