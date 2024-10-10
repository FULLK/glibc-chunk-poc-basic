#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
int main()
{   
    malloc(0x10); //init heap
    size_t chunkarray[0x8];
    chunkarray[1]=0x30; ///-1  0x18 
    free(&chunkarray[2]); //free(&chunkarray[3]); &chunkarray[3] not align 0x10
    size_t destchunk=malloc(0x20);
    printf("fakechunk 0x%p\n",&chunkarray[2]);
    printf("destchunk 0x%p\n",destchunk);

}