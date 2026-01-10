Goal:

Inspired by Hell's Gate technique, we are trying to call Windows syscalls directly (without the help of Windows API functions). The reason for this, from a red teamer's perspective, has to do with EDRs and Windows Function Hooking.

One way that modern EDRs monitor for anomalous and malicous activity is by adding function hooks to certain Windows API functions. These hooks will check who and how a Windows API function is called and if it notices something sketchy, it will notify logs or block the original behavior.

The good thing about these Windows API functions, is that most of them are very simple and have a very similar format. They all look something like this (in x86_64 assembly)

<img width="502" height="390" alt="image" src="https://github.com/user-attachments/assets/9b6d4cda-1033-48d8-bd11-cbad85d09d0e" />

In a hooked function, one of the first two MOV instructions are replaced with a JMP instruction (which jumps into the hook where all the EDR checking happens - once the hook is finished, it will JMP back into this function to call SYSCALL).

So basically, we just need to recreate our own generalized version of the above function. The only variable value we need is the SSN. We implement this in ```syscall_x64.asm```.
Note that Hell's Gate (and we) breaks down the syscall functions into two parts. 1) `StageSyscall` sets up the SSN and 2) `PerformSyscall` does the original Win API functionality 
(above screenshot). It's broken into two parts because we want to keep the second part as close to the original as possible (not add extra arguments).

CustomSyscall.c dynamically finds the SSN (without using WinAPI functions itself) in its ```CustomGetModuleHandle()``` and ```CustomGetProcAddressCustom()``` functions.
You can also find them at [this Github page](https://github.com/j00ru/windows-syscalls/tree/master) for reference (SSN may be different depending on Windows OS verison).

Build:

A little more complicated than others.

```ml64 /c syscall_x64.asm /Fo:syscall_x64.obj```

```cl CustomSyscall.c /Fo:CustomSyscall.obj```

```link CustomSyscall.obj syscall_x64.obj /OUT:CustomSyscall.exe /SUBSYSTEM:CONSOLE```
