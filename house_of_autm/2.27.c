#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

int main()
{
    size_t chunk1=malloc(0x10);
    for(int i=0;i<8;i++)
    {
        free(chunk1);
    }
    size_t* chunk2=malloc(0x10);//tcache
    chunk2[0]=chunk1-0x10;
    malloc(0x10); //fastbin
    size_t* destchunk=malloc(0x10);
    printf("destchunk 0x%p\n",destchunk);
    printf("&chunk1[0]-0x10 0x%p\n",chunk1-0x10);

}