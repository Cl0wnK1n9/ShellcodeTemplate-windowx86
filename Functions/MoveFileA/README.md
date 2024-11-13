## Assembly:
### Tìm hàm
```
code += "push 0xa4048954;" # MoveFileA hash
code += "call dword ptr [ebp+0x4];" # find function
code += "mov [ebp + 0x10], eax;"
```
### Gọi hàm
```
code += "push edi;"                 # con trỏ trỏ đến tên Destination File Path  
code += "push ebx;"                 # con trỏ trỏ đến tên Source File Path
code += "call [ebp + 0x10];"
```
