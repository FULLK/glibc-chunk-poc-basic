#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
size_t getlibc()
{
    puts("getheap\n");
    size_t libc_addr=puts-0x84420;
    return libc_addr;
}
int main()
{
    size_t* chunk1=malloc(0x21000);
    size_t* libc_base=getlibc();
    printf("leak chunk1 %p \n",chunk1);
    printf("leak libc base %p\n",libc_base);
    printf("libc-chunk1= %p\n",libc_base-chunk1);
    

}