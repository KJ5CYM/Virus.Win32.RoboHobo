# Virus.Win32.r0b0h0b0

Now here is a reverse engineering challenge for you!


This slightly stealthy virus was cobbled together mostly from publicly available code on github. I actually did very little real engineering to create this, as this was mostly just proof of concept. I have no real need to create a super powerful computer virus. The graphical effect took far more work and time on my part than the virus itself. 

This is a virus in the truest, yet most basic sense of the word. It's not a worm or trojan or one of those dumb jokes that people call a virus these days. It's just a run of the mill file infector that xor encrypts the virus body, infects, then decrypts and executes when the target executable is run. It is non-destructive unless you allow it to infect a critical system executable. The infection payload consists of a silly message and the virus itself. 

Test it on the exe binaries in the test folder and see if you can learn something from it!

Running the batch file will overwrite the infected executables in the test folder with clean copies, so that you can keep testing.

```
; ==========================================================================================;
; ------------------------------------------------------------------------------------------;
;     FILENAME : robo.exe                                                                   ;
; ------------------------------------------------------------------------------------------;
;       AUTHOR : r0b0h0b0                                                                   ;
;        EMAIL : r0b0h0b0@proton.me                                                         ;
; DATE CREATED : 3/22/2023                                                                  ;
;         TEST : Windows XP (Avast Antivirus, it was undetected)                            ; 
;  DESCRIPTION : Overwriting virus for PE32 exe files in current directory.                 ;
;                Based off Stoned and Joshua viruses, and some shellcode injectors.         ;
;                Will not work while being debugged.                                        ;
; ==========================================================================================;
```
![virustotal](https://github.com/elr0b0h0b0/Virus.Win32.r0b0h0b0/blob/main/r0b0h0b0_VirusTotal.png "virustotal")
