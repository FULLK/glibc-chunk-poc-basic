#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>

int main()
{   

    size_t* chunk1=malloc(0x60);
    size_t* chunk2=malloc(0x60);
   

    free(chunk1);
    free(chunk2);
    free(chunk1);
  
    chunk1=malloc(0x60);
    size_t fake_chunk[4];
    chunk1[0]=fake_chunk;
    fake_chunk[0]=0;
    fake_chunk[1]=0x7f;
    fake_chunk[2]= NULL;
    malloc(0x60);
    malloc(0x60);
    size_t* dest_chunk=malloc(0x60);
    printf("(dest_chunk==fake_chunk[2])= %d\n",dest_chunk==&fake_chunk[2]);
    return 0;
}