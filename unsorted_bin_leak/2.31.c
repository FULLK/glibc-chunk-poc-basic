#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

int main()
{
    size_t* chunk1=malloc(0x410);
    malloc(0x10);
    free(chunk1);
    printf("after afree unsorted bin fd %p bk %p\n",chunk1[0],chunk1[1]);
    size_t* chunk2=malloc(0x10);
    printf("malloc part fd %p bk %p\n",chunk2[0],chunk2[1]);
    
}