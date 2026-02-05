// ml64 /c syscall_x64.asm /Fo:syscall_x64.obj
// cl CustomSyscall.c /Fo:CustomSyscall.obj
//link CustomSyscall.obj syscall_x64.obj /OUT:CustomSyscall.exe /SUBSYSTEM:CONSOLE

#include <Windows.h>
#include <intrin.h>
#include <winternl.h>

HMODULE CustomGetModuleHandle(PWCHAR moduleName) {
	//Get PEB
#ifdef _WIN64
	PPEB pPeb = (PVOID)(__readgsqword(12 * sizeof(PVOID)));
#elif _WIN32
	PPEB pPeb = (PVOID)(__readfsdword(12 * sizeof(PVOID)));
#endif

	//Iterate though modules and find moduleName
	WCHAR dllNameCurrLower[MAX_PATH];
	LIST_ENTRY listEntry = pPeb->Ldr->InMemoryOrderModuleList;
	PLDR_DATA_TABLE_ENTRY pDataTableEntry = listEntry.Flink;
	PLDR_DATA_TABLE_ENTRY pDataTableEntryFirst = listEntry.Flink;

	while (TRUE) {
		printf("%S\n", pDataTableEntry->FullDllName.Buffer);
		//Case insensitive string compare
		if (lstrcmpiA(moduleName, pDataTableEntry->FullDllName.Buffer) == 0) {
			printf("FOUND!\n");
			return (HMODULE)pDataTableEntry->Reserved2[0];
		}

		//next
		pDataTableEntry = pDataTableEntry->Reserved1[0];

		// Break if we reach first element of the circular linked list
		if (pDataTableEntry == pDataTableEntryFirst) {
			break;
		}
	}
	return NULL;
}

PVOID CustomGetProcAddressCustom(HMODULE hModule, PCHAR procName) {
	PBYTE pModuleBase = (PBYTE)hModule;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pModuleBase + pDosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pDirectoryExport = (PIMAGE_EXPORT_DIRECTORY)(pModuleBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD pAddressOfNames = (pModuleBase + (pDirectoryExport->AddressOfNames));
	PWORD pAddressOfOrdinals = (pModuleBase + (pDirectoryExport->AddressOfNameOrdinals));
	PDWORD pAddressOfFunctions = (pModuleBase + (pDirectoryExport->AddressOfFunctions));

	for (int i = 0; i < pDirectoryExport->NumberOfNames; i++) {
		PCHAR procNameCurr = pModuleBase + pAddressOfNames[i];
		if (strcmp(procNameCurr, procName) == 0) {
			return (PVOID)(pModuleBase + pAddressOfFunctions[pAddressOfOrdinals[i]]);
		}
	}

	return NULL;
}

VOID GetSsnFromSyscall(IN PVOID pFunc, OUT PWORD pSsn) {
	
	PBYTE pbFunc = pFunc;
	//First lets read bytes until RET instr
	for (int i = 0; i < 100; i++) {
		//mov r10,rcx # 4C 8BD1 
		//mov eax, <SYSCALL> # B8 <SYSCALL>#  < --Search target
		if( (pbFunc[i] == 0x4C && pbFunc[i+1] == 0x8B && pbFunc[i + 2] == 0xD1) && 
			(pbFunc[i+3] == 0xB8)) {
			*pSsn = pbFunc[i + 4];
			return;
		}
	}
}

int main() {

	printf("Hellow World\n");
	//First we find the Syscall Service Number - note, the inconsisent letter-casing can be normalized (
	//We use custom functions so that we are completely syscall-free
	HMODULE hNtdll = CustomGetModuleHandle(L"ntdll.dll");
	//CustomGetModuleHandle(L"kernel32.dll");
	//CustomGetModuleHandle(L"kernelbase.dll");

	//Parse NtGetCurrentProcessorNumber text section for Syscall Service Number
	PVOID pNtGetCurrentProcessorNumber = CustomGetProcAddressCustom(hNtdll, "NtGetCurrentProcessorNumber");
	DWORD NtGetCurrentProcessorNumberSSN = 0;
	GetSsnFromSyscall(pNtGetCurrentProcessorNumber, &NtGetCurrentProcessorNumberSSN);

	//Now use Syscall Service Number to call syscall directly
	StageSyscall(NtGetCurrentProcessorNumberSSN);
	int status = PerformSyscall(); 
	//Note you can put an arbitrary # of args in PerformSyscall
	//However many the Syscall needs

	printf("%d\n", status);

	return 0;
}
