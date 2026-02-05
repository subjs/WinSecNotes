#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

void PrintLastError(DWORD err) {
	LPVOID msg;
	FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		err,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR)&msg,
		0,
		NULL
	);
	printf("Error %lu: %s\n", err, (char*)msg);
	LocalFree(msg);
}

BOOL OpenPEToByteArray(LPCSTR filepath, BYTE** image, DWORD* image_size) {
	
	HANDLE hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		PrintLastError(GetLastError());
		return FALSE;
	}
	printf("Opened File %S\n", filepath);
	


	LARGE_INTEGER fileSize;
	if (!GetFileSizeEx(hFile, &fileSize)) {
		printf("Error getting file size: %d\n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}

	printf("File Size %lld\n", fileSize.QuadPart);

	*image_size = fileSize.QuadPart;
	*image = malloc(*image_size);

	DWORD bytes_read;
	if (!ReadFile(hFile, *image, *image_size, &bytes_read, NULL)) {
		printf("Error reading file contents: %d\n", GetLastError());
		PrintLastError(GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}

	CloseHandle(hFile);
	return TRUE;
}


BOOL ParseImagePE(BYTE* image, DWORD image_size) {
	printf("ParseImagePE\n");
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)image;

	printf("Magic Number %x\n", dos_header->e_magic);

	if (image[0] != 'M' || image[1] != 'Z') {
		printf("No DOS magic number\n");
		return FALSE;
	}
	printf("Magic number found\n");

	dos_header->e_lfanew; //Fileoffset for NT Header struct

	printf("dos_header->e_lfanew = 0x%p\n", dos_header->e_lfanew);

	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((BYTE*)dos_header + dos_header->e_lfanew);

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		printf("NT HEADER SIGNATURE NOT FOUND\n");
		return FALSE;
	}

	printf("NT Header %lu\n", ntHeaders->Signature);
	printf("IMAGE_NT_SIGNATURE %lu\n", IMAGE_NT_SIGNATURE);
	PIMAGE_FILE_HEADER ntFileHeader = &(ntHeaders->FileHeader);
	
	/*typedef struct _IMAGE_FILE_HEADER {
		WORD    Machine;
		WORD    NumberOfSections;
		DWORD   TimeDateStamp;
		DWORD   PointerToSymbolTable;
		DWORD   NumberOfSymbols;
		WORD    SizeOfOptionalHeader;
		WORD    Characteristics;
	} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;*/
	printf("\nIMAGE FILE HEADER\n");
	printf("nt->FileHeader->Machine = %x\n", ntFileHeader->Machine);
	printf("nt->FileHeader->NumberOfSections = %u\n", ntFileHeader->NumberOfSections);
	printf("nt->FileHeader->TimeDateStamp = %x\n", ntFileHeader->TimeDateStamp);
	printf("nt->FileHeader->PointerToSymbolTable = %lu\n", ntFileHeader->PointerToSymbolTable);
	printf("nt->FileHeader->NumberOfSymbols = %lu\n", ntFileHeader->NumberOfSymbols);
	printf("nt->FileHeader->SizeOfOptionalHeader = %x\n", ntFileHeader->SizeOfOptionalHeader);
	printf("nt->FileHeader->Characteristics = %x\n", ntFileHeader->Characteristics);

	/*typedef struct _IMAGE_OPTIONAL_HEADER64 {
		WORD        Magic;
		BYTE        MajorLinkerVersion;
		BYTE        MinorLinkerVersion;
		DWORD       SizeOfCode;
		DWORD       SizeOfInitializedData;
		DWORD       SizeOfUninitializedData;
		DWORD       AddressOfEntryPoint;
		DWORD       BaseOfCode;
		ULONGLONG   ImageBase;
		DWORD       SectionAlignment;
		DWORD       FileAlignment;
		WORD        MajorOperatingSystemVersion;
		WORD        MinorOperatingSystemVersion;
		WORD        MajorImageVersion;
		WORD        MinorImageVersion;
		WORD        MajorSubsystemVersion;
		WORD        MinorSubsystemVersion;
		DWORD       Win32VersionValue;
		DWORD       SizeOfImage;
		DWORD       SizeOfHeaders;
		DWORD       CheckSum;
		WORD        Subsystem;
		WORD        DllCharacteristics;
		ULONGLONG   SizeOfStackReserve;
		ULONGLONG   SizeOfStackCommit;
		ULONGLONG   SizeOfHeapReserve;
		ULONGLONG   SizeOfHeapCommit;
		DWORD       LoaderFlags;
		DWORD       NumberOfRvaAndSizes;
		IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;*/

	printf("\nIMAGE OPTIONAL HEADER\n");
	PIMAGE_OPTIONAL_HEADER ntOptionalHeader = &(ntHeaders->OptionalHeader);
	if (ntOptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		printf("ntOptionalHeader->Magic 32 bit\n");
	}
	else if (ntOptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		printf("ntOptionalHeader->Magic 64 bit\n");
	}

	DWORD64 ImageBase = ntOptionalHeader->ImageBase;
	DWORD SizeOfImage = ntOptionalHeader->SizeOfImage;
	DWORD AddressOfEntryPointOffset = ntOptionalHeader->AddressOfEntryPoint;

	PIMAGE_DATA_DIRECTORY pDataDirectoryExport = &(ntOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	PIMAGE_DATA_DIRECTORY pDataDirectoryImport = &(ntOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	PIMAGE_DATA_DIRECTORY pDataDirectoryReloc = &(ntOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	PIMAGE_DATA_DIRECTORY pDataDirectoryException = &(ntOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]);

	LPVOID pBufInMemPE;
	pBufInMemPE = VirtualAlloc(NULL, SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	
	if (pBufInMemPE == NULL) {
		printf("Error allocating memory for PE Image\n");
		return FALSE;
	}

	WORD numOfSections = ntFileHeader->NumberOfSections;
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	
	//Here we iterate through all the sections of the PE file and copy them over to the PE Image heap space we just allocated
	for (int i = 0; i < numOfSections; i++) {
		IMAGE_SECTION_HEADER sectionHeader = pSectionHeader[i];
		printf("Copying over %s\n", sectionHeader.Name);
		memcpy((DWORD64)pBufInMemPE + sectionHeader.VirtualAddress, (DWORD64)image + sectionHeader.PointerToRawData, sectionHeader.SizeOfRawData);
	}

	//Figuring out our relocation data
	DWORD totalBaseRelocationEntries = pDataDirectoryReloc->Size ;
	//We calculate the needed offset by:
	DWORD64 relocOffset = (DWORD64)pBufInMemPE - ImageBase;
	printf("Relocation Offset %lu\n", relocOffset);
	//Now we will find all of the offset that we need to adjust(using the relocation table)

	printf("Total Number of IMAGE_BASE_RELOCATION_ENTRY entries %x\n", totalBaseRelocationEntries);

	typedef struct _IMAGE_BASE_RELOCATION_ENTRY {
		WORD Offset : 12;
		WORD Type : 4;
	} IMAGE_BASE_RELOCATION_ENTRY, * PIMAGE_BASE_RELOCATION_ENTRY;

	PIMAGE_BASE_RELOCATION pImageBaseRelocation = (DWORD64)pBufInMemPE + pDataDirectoryReloc->VirtualAddress;
	BYTE* relocBase = pImageBaseRelocation;
	BYTE* relocEnd = pImageBaseRelocation + pDataDirectoryReloc->Size;

	while (relocBase < relocEnd) {
		PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)relocBase;
		if (block->VirtualAddress == 0) { break; }
		DWORD imageBaseRelocationBlockSize = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/ sizeof(IMAGE_BASE_RELOCATION_ENTRY);
		printf("IMAGE_BASE_RELOCATION VA is 0x%x\n", block->VirtualAddress);
		printf("IMAGE_BASE_RELOCATION size is 0x%x\n", imageBaseRelocationBlockSize);

		PIMAGE_BASE_RELOCATION_ENTRY pRelocationEntry = (PIMAGE_BASE_RELOCATION_ENTRY)((DWORD64)relocBase + sizeof(IMAGE_BASE_RELOCATION));
		for (int i = 0; i < imageBaseRelocationBlockSize; i++) {
			DWORD64 relocAt = (DWORD64)pBufInMemPE + block->VirtualAddress + (pRelocationEntry[i]).Offset;

			printf("Offset 0x%X  Type %X\n", (pRelocationEntry[i]).Offset, (pRelocationEntry[i]).Type);
			switch ((pRelocationEntry[i]).Type){
				case IMAGE_REL_BASED_HIGH:
					*(PWORD)relocAt += HIWORD(relocOffset);
					break;
				case IMAGE_REL_BASED_LOW:
					*(PWORD)relocAt += LOWORD(relocOffset);
					break;
				case IMAGE_REL_BASED_HIGHLOW:
					*(PDWORD)relocAt += (DWORD)relocOffset;
					break;
				case IMAGE_REL_BASED_DIR64:
					*(PDWORD64)relocAt += relocOffset;
					break;
				case IMAGE_REL_BASED_ABSOLUTE:
				default:
					break;
			}
		}
		relocBase += block->SizeOfBlock;
	}
	printf("Finished Relocating things\n");


	//Now we fix imports
	IMAGE_IMPORT_DESCRIPTOR;
	IMAGE_THUNK_DATA;
	pDataDirectoryImport->Size;
	pDataDirectoryImport->VirtualAddress;
	printf("Fixing Imports\n");
	printf("Import Descriptor array size %lu\n", pDataDirectoryImport->Size);
	printf("Import Descriptor array VA 0x%X\n", pDataDirectoryImport->VirtualAddress);
	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = (DWORD64)pBufInMemPE + pDataDirectoryImport->VirtualAddress;
	DWORD numDataDirectoryImports = pDataDirectoryImport->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	//First we iterate to get all names
	while (pImageImportDescriptor->FirstThunk != NULL && pImageImportDescriptor->OriginalFirstThunk != NULL) {
		PCHAR dllName = (PCHAR)pBufInMemPE + pImageImportDescriptor->Name;
		printf("pImageImportDescriptor[i].Name %s\n", dllName);
		HMODULE hModule = GetModuleHandleA(dllName);
		if (hModule == INVALID_HANDLE_VALUE || hModule == NULL) {
			hModule = LoadLibraryA(dllName);
			if (hModule == INVALID_HANDLE_VALUE || hModule == NULL) {
				printf("Error: GetModuleHandle\n");
				return FALSE;
			}
		}

		//Take Imports from OriginalFirstThunk(INT) and patch the FirstThunk(IAT)
		printf("Take Imports from OriginalFirstThunk(INT) and patch the FirstThunk(IAT)\n");
		PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA) ((BYTE*)pBufInMemPE + pImageImportDescriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA) ((BYTE*)pBufInMemPE  + pImageImportDescriptor->FirstThunk);
		BOOL isOrdinal = FALSE;
		while(pOriginalFirstThunk->u1.AddressOfData != NULL && pFirstThunk->u1.AddressOfData){
			isOrdinal = ((pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0 ? FALSE : TRUE);
			LPVOID funcAddress = NULL;
			PIMAGE_IMPORT_BY_NAME pImageImportByName;
			if (isOrdinal) {
				printf("\Ordinal: %llu\n", pOriginalFirstThunk->u1.Ordinal);
				funcAddress = GetProcAddress(hModule, IMAGE_ORDINAL(pOriginalFirstThunk->u1.Ordinal));
			} else {
				pImageImportByName = (PIMAGE_IMPORT_BY_NAME) ((BYTE*)pBufInMemPE + pOriginalFirstThunk->u1.AddressOfData);
				printf("\tName: %s\n", pImageImportByName->Name);
				funcAddress = GetProcAddress(hModule, pImageImportByName->Name);
			}
			if (funcAddress == 0) {
				printf("Error: GetProcAddress\n");
				return FALSE;
			}
			//set found address from INT to IAT
			pFirstThunk->u1.Function = funcAddress;
			pOriginalFirstThunk++;
			pFirstThunk++;

		}
		pImageImportDescriptor++;

	}
	printf("Now we must register exception handlers\n");
	RUNTIME_FUNCTION;
	if (pDataDirectoryException->VirtualAddress != NULL) {
		PRUNTIME_FUNCTION pFunctionTable = (PRUNTIME_FUNCTION)((BYTE*)pBufInMemPE + pDataDirectoryException->VirtualAddress);
		if (!RtlAddFunctionTable(pFunctionTable, (pDataDirectoryException->Size / sizeof(RUNTIME_FUNCTION)),pBufInMemPE)) {
			printf("RtlAddFunctionTable\n");
			return FALSE;
		}
	}

	printf("Iterate through all sections and change permissions\n");
	for (int i = 0; i < numOfSections; i++) {
		IMAGE_SECTION_HEADER sectionHeader = pSectionHeader[i];
		DWORD newProtection = 0, oldProtection = 0;
		// Get correct permission to set
		if ((sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) && !(sectionHeader.Characteristics & IMAGE_SCN_MEM_READ) && !(sectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE)) {
			newProtection = PAGE_EXECUTE;
			printf("PAGE_EXECUTE\n");
		}
		else if ((sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sectionHeader.Characteristics & IMAGE_SCN_MEM_READ) && !(sectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE)) {
			newProtection = PAGE_EXECUTE_READ;
			printf("PAGE_EXECUTE_READ\n");
		}
		else if ((sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sectionHeader.Characteristics & IMAGE_SCN_MEM_READ) && (sectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE)) {
			newProtection = PAGE_EXECUTE_READWRITE;
			printf("PAGE_EXECUTE_READWRITE\n");
		}
		else if (!(sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sectionHeader.Characteristics & IMAGE_SCN_MEM_READ) && !(sectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE)) {
			newProtection = PAGE_READONLY;
			printf("PAGE_READONLY\n");
		}
		else if (!(sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sectionHeader.Characteristics & IMAGE_SCN_MEM_READ) && (sectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE)) {
			newProtection = PAGE_READWRITE;
			printf("PAGE_READWRITE\n");
		}
		else {
			printf("ELSE????\n");
			return FALSE;
		}

		if (!VirtualProtect( (LPVOID)((BYTE*)pBufInMemPE + sectionHeader.VirtualAddress), sectionHeader.Misc.VirtualSize, newProtection, &oldProtection)) {
			printf("VirtualProtect section error\n");
			PrintLastError(GetLastError());
			return FALSE;
		}
	}

	printf("Now we modify our PEB to update the commandline from this loader to the image\n");
#ifdef _M_X64
	PPEB pPeb = (PPEB) __readgsqword(12*sizeof(PVOID));
#else
	PPEB pPeb = (PPEB)__readfsqword(12 * sizeof(PVOID));
#endif
	USHORT originalLen = pPeb->ProcessParameters->CommandLine.Length;
	PWSTR originalCommandline;// = VirtualAlloc(NULL, originalLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	originalCommandline = VirtualAlloc(NULL, originalLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (originalCommandline) {
		memcpy(originalCommandline, pPeb->ProcessParameters->CommandLine.Buffer, originalLen);
	}
	pPeb->ProcessParameters->CommandLine.Buffer[0] = L'Z';
	printf("Current Command Line %S\n", pPeb->ProcessParameters->CommandLine.Buffer);
	printf("DONE\n");
	VirtualFree(originalCommandline, NULL, MEM_RELEASE);

	printf("Now we will jump to the entry point of our in memory PE\n");
	LPVOID pEntry = (BYTE*)pBufInMemPE + ntOptionalHeader->AddressOfEntryPoint;
	typedef BOOL(*DLLMAIN)(HINSTANCE, DWORD, LPVOID);
	typedef BOOL(*MAIN)(DWORD, PCHAR);
	
	//if DLL
	if((ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL)){
		((DLLMAIN)pEntry) (pBufInMemPE, DLL_PROCESS_ATTACH, NULL);
	}
	else {
		((MAIN)pEntry)(1, NULL);
	}
	VirtualFree(pBufInMemPE, NULL, MEM_RELEASE);
	return TRUE;
}

int main(int argc, char* argv[]) {
	printf("DLL Parser + Loader\n");
	if (argc < 2) {
		printf("Usage: %s [dll] [optional PID]\n", argv[0]);
		return 1;
	}

	BYTE* image;
	DWORD image_size;
	OpenPEToByteArray(argv[1], &image, &image_size);
	
	if (!ParseImagePE(image, image_size, NULL)) {
		printf("Error with PE format\n");
	}
	else {
		printf("Successfuly parsed PE format\n");
	}

	free(image);
	return 0;
}
