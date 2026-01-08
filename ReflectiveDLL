Goal:

This technique is to manually take a Windows Portable Executable (like an EXE or DLL), and move the appropriate data sections in place to be executed. The benefit of doing it this particular way (rather than using CreateProcess() or LoadLibrary() winapi calls) is that the PE filedata does not have to be on disk filesystem. 

For a red teamer, this means that any EDRs that are scanning the filesystem for sketchy files will not find your PE file (since it is never written to the disk filesystem).

Learning this is also a good way to familiarize yourself with the PE file format, and what all of the headers and sections are for.

The basic steps to Reflectively Load a DLL are:

<Assume you have your PE filedata in a buffer already - maybe you got it from an encrypted blob from the filesystem or over a network connection >


------ First we move the PE file sections to the right place ------
1) Parse the DOS header to find the PE header (DOS_header->e_lfanew is the offset to the PE header)
2) Get the PE_header->OptionalHeader for the data we need
3) Allocate memory of size PE_header->OptionalHeader->SizeOfImage 
4) Iterate through all the sections of PE_headers. Each section has a section header - we now copy the sectionHeader.SizeOfRawData amount of data from  sectionHeader.PointerToRawData to  sectionHeader.VirtualAddress
5) Check which sections need to relocated, and relocate them by the calculated offset.
6) Fix Imports, resolve Import Name Table to Import Address Table
7) Register Exception handlers
8) Iterate through all section and change their permissions
< Optional - modify PEB commandline >
9) Jump to entry point of our in-memory PE
