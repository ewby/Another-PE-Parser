#include "Windows.h"
#include <stdio.h>
#include <time.h>

int main(int argc, char *argv[])
{
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    HANDLE hFile, hFileMap;
    LPVOID lpFileBaseAddress = NULL;

    if (argc < 2)
    {
        printf("Usage: %s <Path to PE file>\n", argv[0]);
        return -1;
    }

    hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            printf("Failed to open the PE file: %s\n", argv[1]);
            return 1;
        }

    // Map file for memory efficiency and ease of access to pointers for PE sections
    hFileMap = CreateFileMapping(hFile, 0, PAGE_READONLY, 0, 0, NULL);
        if (hFileMap == INVALID_HANDLE_VALUE)
        {
            printf("Failed to map the PE file into memory\n");
            CloseHandle(hFile);
            return 1;
        }

    lpFileBaseAddress = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
        if (lpFileBaseAddress == NULL)
        {
            printf("Failed to map the PE file into memory\n");
            CloseHandle(hFileMap);
            CloseHandle(hFile);
            return 1;
        }
    
    // Get DOS Header
    pDosHeader = (PIMAGE_DOS_HEADER)lpFileBaseAddress;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            printf("Invalid DOS header\n");
            UnmapViewOfFile(lpFileBaseAddress);
            CloseHandle(hFileMap);
            CloseHandle(hFile);
            return 1;
        }

    // Get NT Headers
    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((BYTE*)lpFileBaseAddress + pDosHeader->e_lfanew);

    // Get Optional Header. This is an extra step purely just to practice messing with the data, in future projects I'll skip directly to the Import Table.
    PIMAGE_OPTIONAL_HEADER64 pOptionalHeader = &pNtHeaders->OptionalHeader;

    // Get Import Table from Optional Header
    PIMAGE_DATA_DIRECTORY pImportTable = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        // Get Import Descriptor
        if (pImportTable->VirtualAddress != 0)
        {
            PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)lpFileBaseAddress + pImportTable->VirtualAddress);
        }

    // Print values, sticking to hex where reasonable
    printf("\n[+] DOS Header\n");
    printf("\n\tMagic Number: \t\t\t\t0x%x\n", pDosHeader->e_magic);
    printf("\tBytes on Last Page of File: \t\t0x%x\n", pDosHeader->e_cblp);
    printf("\tPages in File: \t\t\t\t0x%x\n", pDosHeader->e_cp);
    printf("\tRelocations: \t\t\t\t0x%x\n", pDosHeader->e_crlc);
    printf("\tSize of Header in Paragraphs: \t\t0x%x\n", pDosHeader->e_cparhdr);
    printf("\tMinimum Extra Paragraphs Needed: \t0x%x\n", pDosHeader->e_minalloc);
    printf("\tMaximum Extra Paragraphs Needed: \t0x%x\n", pDosHeader->e_maxalloc);
    printf("\tInitial (Relative) SS Value: \t\t0x%x\n", pDosHeader->e_ss);
    printf("\tInitial SP Value: \t\t\t0x%x\n", pDosHeader->e_sp);
    printf("\tChecksum: \t\t\t\t0x%x\n", pDosHeader->e_csum);
    printf("\tInitial IP Value: \t\t\t0x%x\n", pDosHeader->e_ip);
    printf("\tInitial (Relative) CS Value: \t\t0x%x\n", pDosHeader->e_cs);
    printf("\tFile Address of Relocation Table: \t0x%x\n", pDosHeader->e_lfarlc);
    printf("\tOverlay Number: \t\t\t0x%x\n", pDosHeader->e_ovno);
    printf("\tOEM Identifier (For e_oeminfo): \t0x%x\n", pDosHeader->e_oemid);
    printf("\tOEM Information; e_oemid Specific: \t0x%x\n", pDosHeader->e_oeminfo);
    printf("\tReserved Words: \t\t\t0x%x\n", pDosHeader->e_res2);
    printf("\tFile Address of New EXE Header: \t0x%lx\n", pDosHeader->e_lfanew);

    // Nicer printing of PE timestamp
    time_t timestamp = pNtHeaders->FileHeader.TimeDateStamp;
    char* timestr = ctime(&timestamp);

    printf("\n[+] NT Headers\n");
    printf("\n\tSignature: %c%c\n", ((char *)&(pNtHeaders->Signature))[0], ((char *)&(pNtHeaders->Signature))[1]);

    // File Header struct-ception
    printf("\n[+] NT Headers -> File Header Struct\n");
    printf("\n\tMachine: \t\t\t%x\n", pNtHeaders->FileHeader.Machine);
    printf("\tNumber of Sections: \t\t%hu\n", pNtHeaders->FileHeader.NumberOfSections);
    printf("\tTime Date Stamp: \t\t0x%08lx, %s", pNtHeaders->FileHeader.TimeDateStamp, timestr);
    printf("\tPointer to Symbol Table: \t0x%lu\n", pNtHeaders->FileHeader.PointerToSymbolTable);
    printf("\tNumber of Symbols: \t\t0x%lx\n", pNtHeaders->FileHeader.NumberOfSymbols);
    printf("\tSize of Optional Header: \t0x%x\n", pNtHeaders->FileHeader.SizeOfOptionalHeader);
    printf("\tCharacteristics: \t\t0x%x\n", pNtHeaders->FileHeader.Characteristics);

    // Optional Header struct-ception
    printf("\n[+] NT Headers -> Optional Header Struct\n");
    printf("\n\tMagic Byte: \t\t\t\t0x%x\n", pOptionalHeader->Magic);
    printf("\tMajor Linker Version: \t\t\t0x%x\n", pOptionalHeader->MajorLinkerVersion);
    printf("\tMinor Linker Version: \t\t\t0x%x\n", pOptionalHeader->MinorLinkerVersion);
    printf("\tSize of Code: \t\t\t\t0x%lx\n", pOptionalHeader->SizeOfCode);
    printf("\tSize of Initialized Data: \t\t0x%lx\n", pOptionalHeader->SizeOfInitializedData);
    printf("\tSize of Uninitialized Data: \t\t0x%lx\n", pOptionalHeader->SizeOfUninitializedData);
    printf("\tAddress of Entry Point: \t\t0x%lx\n", pOptionalHeader->AddressOfEntryPoint);
    printf("\tBase of Code: \t\t\t\t0x%lx\n", pOptionalHeader->BaseOfCode);
    printf("\tImage Base: \t\t\t\t0x%llx\n", pOptionalHeader->ImageBase);
    printf("\tSection Alignment: \t\t\t0x%lx\n", pOptionalHeader->SectionAlignment);
    printf("\tFile Alignment: \t\t\t0x%lx\n", pOptionalHeader->FileAlignment);
    printf("\tMajor Operating System Version: \t0x%x\n", pOptionalHeader->MajorOperatingSystemVersion);
    printf("\tMinor Operating System Version: \t0x%x\n", pOptionalHeader->MinorOperatingSystemVersion);
    printf("\tMajor Image Version: \t\t\t0x%x\n", pOptionalHeader->MajorImageVersion);
    printf("\tMinor Image Version: \t\t\t0x%x\n", pOptionalHeader->MinorImageVersion);
    printf("\tMajor Subsystem Version: \t\t0x%x\n", pOptionalHeader->MajorSubsystemVersion);
    printf("\tMinor Subsystem Version: \t\t0x%x\n", pOptionalHeader->MinorSubsystemVersion);
    printf("\tWin32 Version Value: \t\t\t0x%lx\n", pOptionalHeader->Win32VersionValue);
    printf("\tSize of Image: \t\t\t\t0x%lx\n", pOptionalHeader->SizeOfImage);
    printf("\tSize of Headers: \t\t\t0x%lx\n", pOptionalHeader->SizeOfHeaders);
    printf("\tChecksum: \t\t\t\t0x%lx\n", pOptionalHeader->CheckSum);
    printf("\tSubsystem: \t\t\t\t0x%x\n", pOptionalHeader->Subsystem);
    printf("\tDLL Characteristics: \t\t\t0x%x\n", pOptionalHeader->DllCharacteristics);
    printf("\tSize of Stack Reserve: \t\t\t0x%llx\n", pOptionalHeader->SizeOfStackReserve);
    printf("\tSize of Stack Commit: \t\t\t0x%llx\n", pOptionalHeader->SizeOfStackCommit);
    printf("\tSize of Heap Reserve: \t\t\t0x%llx\n", pOptionalHeader->SizeOfHeapReserve);
    printf("\tSize of Heap Commit: \t\t\t0x%llx\n", pOptionalHeader->SizeOfHeapCommit);
    printf("\tLoader Flags: \t\t\t\t0x%lx\n", pOptionalHeader->LoaderFlags);
    printf("\tNumber of RVA and Sizes: \t\t0x%lx\n", pOptionalHeader->NumberOfRvaAndSizes);

    
    printf("\n[+] Data Directory\n");
    printf("\n\tImport Directory Virtual Address: \t%lx\n", pImportTable->VirtualAddress);

    return 0;
}