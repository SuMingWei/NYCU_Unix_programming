import pow as pw
import base64
from pwn import *

r = remote('up23.zoolab.org', 10363)
pw.solve_pow(r)

# r.interactive()
trash = r.recvuntil("complete the ")
problem = (r.recvuntil("challenges ").decode().split(" ")[0])
problem = int(problem)
print(problem)
# get question num
for i in range(1, problem+1):
    trash = r.recvuntil(str(i) + ":")
    qes = str(r.recvuntil("= ")).split(" ")
    num1 = qes[1]
    op = qes[2]
    num2 = qes[3]
    print(num1, op, num2)

    # solve
    ans = 0
    if op == "+":
        ans = int(num1) + int(num2)
    elif op == "-":
        ans = int(num1) - int(num2)
    elif op == "*":
        ans = int(num1) * int(num2)
    elif op == "/":
        ans = int(num1) / int(num2)
    elif op == "**":
        ans = int(num1) ** int(num2)
    elif op == "//":
        ans = int(num1) // int(num2)
    elif op == "%":
        ans = int(num1) % int(num2)
        
    print(ans)
    # result = struct.pack('<q', int(hex(ans), base=16))
    result = ans.to_bytes((ans.bit_length() + 7) // 8, byteorder="little")
    # result = bytearray.fromhex(hex(ans))[::-1]
    print(result)
    result = base64.b64encode(result)
    print(result)
    r.sendlineafter(b'? ', result)
    
r.interactive()
r.close()

