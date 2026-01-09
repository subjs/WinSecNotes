#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <psapi.h>

int main() {
	printf("Hello World\n");

	HANDLE process = GetCurrentProcess();
	MODULEINFO mi = {0};
	HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");

	GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
	LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll; //This is ntdll mapped in the current process
	HANDLE ntdllFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE ntdllMapping = CreateFileMapping(ntdllMapping, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS64 hookedNtHeader = (PIMAGE_NT_HEADERS64)((DWORD64)ntdllBase + hookedDosHeader->e_lfanew);


	printf("%lu\n", hookedNtHeader->FileHeader.NumberOfSections);
	for (WORD i = 0; i < ((PIMAGE_NT_HEADERS)hookedNtHeader)->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER*i));

		if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
			DWORD oldProtection = 0;
			BOOL isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			memcpy(
				(BYTE*)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress),
				(BYTE*)(DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress,
				hookedSectionHeader->Misc.VirtualSize);
			isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
		}
	}

	//Note that if this is for a NOT ntdll (or kernel32)  dll, then we have to do image relocations - similar to how we did in reflective DLL loading
	CloseHandle(process);
	CloseHandle(ntdllFile);
	CloseHandle(ntdllMapping);
	CloseHandle(ntdllModule);
	return 0;
}
