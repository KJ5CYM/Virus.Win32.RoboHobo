# Virus.Win32.RoboHobo v5.6

Meet RoboHobo, my modern-ish computer virus.

This virus was created on and for Windows XP, but it works on Windows 7 and Windows 10. It will be deleted by Windows Defender, however.

This is a virus in the truest, yet most basic sense of the word. It's not a worm or trivial trojan or one of those stupid jokes that people call a virus these days. It's just a run of the mill file infector that xor encrypts the virus body, finds and infects EXE files in the current directory, then decrypts and executes when the infected PE is run. It is non-destructive unless you allow it to infect a critical system executable. The infection payload consists of a silly message and the virus itself.

Test it on the exe binaries in the test folder, disassemble it, use it as inspiration, just see if you can learn something from it!

Running the batch file will overwrite the infected executables in the test folder with clean copies, so that you can keep testing.

```
; ==========================================================================================;
; ------------------------------------------------------------------------------------------;
;     FILENAME : r0b0h0b0.asm                                                               ;
; ------------------------------------------------------------------------------------------;
;       AUTHOR : r0b0h0b0                                                                   ;
;        EMAIL : r0b0h0b0@proton.me                                                         ;
; DATE CREATED : 3/22/2023                                                                  ;
;         TEST : Windows XP (Avast Antivirus, it was undetected)                            ; 
;  DESCRIPTION : Overwriting virus for PE32 exe files in current directory.                 ;
;                Based off Stoned and Joshua viruses, and some shellcode injectors.         ;
; ==========================================================================================;
```

## Demo:
![demo](https://github.com/elr0b0h0b0/Virus.Win32.r0b0h0b0/blob/main/demo.gif "demo")
![virustotal](https://github.com/elr0b0h0b0/Virus.Win32.r0b0h0b0/blob/main/r0b0h0b0_VirusTotal.png "virustotal")

Interstingly, Windows Defender on Windows 10 thinks it is a trojan, which it is not. It's just a virus, and it has no networking capabilities. If you want to play with it on Windows 10/11, you'll have to go to Windows Defender and "Allow Threat." When you're done, you should re-enable Windows Defender.

![windefend](https://github.com/elr0b0h0b0/Virus.Win32.r0b0h0b0/blob/main/false_identify.png "windefend")
