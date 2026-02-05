#include <windows.h>

void PrintMyIAT()
{
    HMODULE base = GetModuleHandle(NULL);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);

    IMAGE_DATA_DIRECTORY importDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (importDir.VirtualAddress == 0)
        return;

    PIMAGE_IMPORT_DESCRIPTOR impDesc =
        (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)base + importDir.VirtualAddress);

    for (; impDesc->Name != 0; impDesc++)
    {
        LPCSTR dllName = (LPCSTR)((BYTE*)base + impDesc->Name);
        printf("DLL: %s\n", dllName);

        PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)((BYTE*)base + impDesc->FirstThunk);

        for (; iat->u1.Function != 0; iat++)
        {
            FARPROC fnPtr = (FARPROC)iat->u1.Function;
            printf("  IAT entry -> %p\n", fnPtr);
        }
    }
}

int main(){
    HANDLE base = GetModuleHandle(NULL);

    HMODULE hUser32 = GetModuleHandle("Kernel32.dll");

    FARPROC pWinExec = GetProcAddress(hUser32, "WinExec");
    FARPROC pExitProcess = GetProcAddress(hUser32, "ExitProcess");

    printf("WinExec = %p\n", pWinExec);
    printf("ExitProcess = %p\n", pExitProcess);

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((BYTE*)dos_header + dos_header->e_lfanew);
    IMAGE_DATA_DIRECTORY importDir = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    PIMAGE_IMPORT_DESCRIPTOR impDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)base + importDir.VirtualAddress);
    for (;impDesc->Name != 0; impDesc++) {
        LPCSTR dllName = (LPCSTR)((BYTE*)base + impDesc->Name);
        printf("%s\n", dllName);
        PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)((BYTE*)base + impDesc->FirstThunk);

        for (; iat->u1.Function != 0; iat++)
        {
            FARPROC fnPtr = (FARPROC)iat->u1.Function;
            printf("  IAT entry -> %p\n", fnPtr);
        }
    }

    printf("%p\n", base);
    printf("%p\n", nt_header);
    PrintMyIAT();
    return 0;
}
