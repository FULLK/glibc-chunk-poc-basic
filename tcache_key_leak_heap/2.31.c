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
    size_t* chunk1=malloc(0x20);
    free(chunk1);
    size_t* key=chunk1[1];
    size_t* heapbase_fd=getheap()+0x10;

    printf("heapbase memory part %p\n",heapbase_fd);
    printf("chunk key %p\n",key);
}