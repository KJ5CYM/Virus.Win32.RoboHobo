# Virus.Win32.r0b0h0b0

Now here is a reverse engineering challenge for you!
This virus was cobbled together from publicly available code on github. I actually did very little engineering to create this. The graphical effect was more work than the virus itself. A virus in the truest sense of the word, it's not a trojan or one of those dumb jokes that people call "viruses" these days. It is non destructive unless you allow it to infect a critical system executable. The infection payload consists of a silly message and the virus itself. See if you can learn something from it!

```
; ==========================================================================================;
; ------------------------------------------------------------------------------------------;
;     FILENAME : r0b0h0b0.exe                                                               ;
; ------------------------------------------------------------------------------------------;
;       AUTHOR : r0b0h0b0                                                                   ;
;        EMAIL : r0b0h0b0@proton.me                                                         ;
; DATE CREATED : 3/22/2023                                                                  ;
;         TEST : Windows XP (Avast Antivirus)                                               ; 
;  DESCRIPTION : Overwriting virus for PE32 exe files in current directory.                 ;
;                Based off Stoned and Joshua viruses, and some shellcode injectors.         ;
;                Will not work while being debugged.                                        ;
; ==========================================================================================;
```
![virustotal](https://github.com/elr0b0h0b0/Virus.Win32.r0b0h0b0/blob/main/r0b0h0b0_VirusTotal.png "virustotal")
