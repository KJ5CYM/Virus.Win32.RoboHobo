@echo off

if exist Adept.exe del Adept.exe
if exist procexp.exe del procexp.exe

copy procexp.exe.bak procexp.exe
copy Adept.exe.bak Adept.exe