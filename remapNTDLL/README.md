Goal

This code finds the original ntdll code and maps it to the current process's ntdll mapping. One reason a red teamer may want to do this is if an EDR service adds hooks to ntdll functions -- hooks that might be checking how Syscalls are called --
this method can wipe away those hooks. In practice, however, the EDR may be 1) hooked into the CreateFile function and checking for strange processes that are trying to open C:\\Windows\\System32\\ntdll.dll 2)checking VirtualProtect() and investigating/blocking
if a process is trying to make an EXECUTE data section into WRITE temporarily.

Still an interesting learning exercise though.


Build

```cl remapNtdll.c /o remapNtdll.exe```

NOTE: There are no visible effects of this exercise atm. 
