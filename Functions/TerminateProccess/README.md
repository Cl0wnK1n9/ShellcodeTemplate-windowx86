## Assembly:
### Tìm hàm
```
code += "push 0x78b5b983;" # TerminateProcess
code += "call dword ptr [ebp + 0x4];" # call find_function
code += "mov [ebp + 0x10], eax;" # save TerminateProcess 
```
### Gọi hàm
```
code += "push 0x11223344;" # uExitCode
code += "push 0xffffffff;" # hProcess
code += "call [ebp + 0x10];"
```
