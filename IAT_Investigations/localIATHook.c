#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <psapi.h>

#pragma comment(lib, "user32.lib")

typedef int (WINAPI* PrototypeMessageBox)(HWND, LPCSTR, LPCSTR, UINT);

PrototypeMessageBox originalMsgBox = 0;

int hookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	MessageBoxW(NULL, L"NEW HOOKed Message Box", L"NEW HOOKed Message Caption", 0);
	return originalMsgBox(hWnd, lpText, lpCaption, uType);
}

void localHook() {
	originalMsgBox = MessageBoxA;

	//MessageBox before IAT hook
	MessageBoxA(NULL, "Before hook", "Before hook caption", 0);

	LPVOID imageBase = GetModuleHandleA(NULL);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importDirectory.VirtualAddress + (DWORD_PTR)imageBase);
	LPCSTR libraryName = NULL;
	HMODULE library = NULL;
	PIMAGE_IMPORT_BY_NAME functionName = NULL;

	while (importDescriptor->Name != NULL) {
		libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)imageBase;
		library = LoadLibraryA(libraryName);
		//printf("%s\n", libraryName);
		if (library) {
			PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
			originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
			firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);

			while (originalFirstThunk->u1.AddressOfData != NULL) {
				functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData);
				//printf("%s\n", functionName->Name);
				if (strncmp((PCHAR)functionName->Name, "MessageBoxA", 11) == 0) {
					//printf("Found MessageBoxA\n");
					SIZE_T bytesWritten = 0;
					DWORD oldProtect = 0;
					VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect);

					firstThunk->u1.Function = (DWORD_PTR)hookedMessageBox;
				}
				originalFirstThunk++;
				firstThunk++;
			}
		}
		importDescriptor++;
	}

	//Post IAT Hooking
	MessageBoxA(NULL, "After hook", "After hook caption", 0);
}


int main() {
	localHook();
	return 0;
}
