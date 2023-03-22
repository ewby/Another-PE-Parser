#include "Windows.h"
#include <stdio.h>
#include <time.h>

// Put in a .h file
typedef unsigned long long QWORD;

int main(int argc, char *argv[])
{
    PIMAGE_DOS_HEADER dos_header = NULL; //was {}
    HANDLE hFile, hFileMap;
    LPVOID fileData = NULL;

    if (argc < 2) {
        printf("Usage: %s <Path to PE file>\n", argv[0]);
        return -1;
    }

    hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
        return -1;

    // Map file for memory efficiency and ease of access to pointers for PE sections
    hFileMap = CreateFileMapping(hFile, 0, PAGE_READONLY, 0, 0, NULL);
    if (hFileMap == INVALID_HANDLE_VALUE)
        return -1;

    fileData = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);

    dos_header = (PIMAGE_DOS_HEADER)fileData;

    // Print hexadecimal, because PE file format. %08x for 32-bit hexadecimal
    printf("\n[+] DOS Header\n");
    printf("\n\tMagic Number: \t\t\t\t0x%x\n", dos_header->e_magic);
    printf("\tBytes on Last Page of File: \t\t0x%x\n", dos_header->e_cblp);
    printf("\tPages in File: \t\t\t\t0x%x\n", dos_header->e_cp);
    printf("\tRelocations: \t\t\t\t0x%x\n", dos_header->e_crlc);
    printf("\tSize of Header in Paragraphs: \t\t0x%x\n", dos_header->e_cparhdr);
    printf("\tMinimum Extra Paragraphs Needed: \t0x%x\n", dos_header->e_minalloc);
    printf("\tMaximum Extra Paragraphs Needed: \t0x%x\n", dos_header->e_maxalloc);
    printf("\tInitial (Relative) SS Value: \t\t0x%x\n", dos_header->e_ss);
    printf("\tInitial SP Value: \t\t\t0x%x\n", dos_header->e_sp);
    printf("\tChecksum: \t\t\t\t0x%x\n", dos_header->e_csum);
    printf("\tInitial IP Value: \t\t\t0x%x\n", dos_header->e_ip);
    printf("\tInitial (Relative) CS Value: \t\t0x%x\n", dos_header->e_cs);
    printf("\tFile Address of Relocation Table: \t0x%x\n", dos_header->e_lfarlc);
    printf("\tOverlay Number: \t\t\t0x%x\n", dos_header->e_ovno);
    printf("\tOEM Identifier (For e_oeminfo): \t0x%x\n", dos_header->e_oemid);
    printf("\tOEM Information; e_oemid Specific: \t0x%x\n", dos_header->e_oeminfo);
    printf("\tReserved Words: \t\t\t0x%x\n", dos_header->e_res2);
    printf("\tFile Address of New EXE Header: \t0x%x\n", dos_header->e_lfanew);

    /*

     Need to research why I can't use "nt_headers = (PIMAGE_NT_HEADERS64)fileData + dos_header->e_lfanew;", something about casting

            typedef struct _IMAGE_NT_HEADERS64 {
          DWORD                   Signature;
          IMAGE_FILE_HEADER       FileHeader;
          IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        } IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

     IMAGE_FILE_HEADER and IMAGE_OPTIONAL_HEADER64 are both structs, need to print those as well

     */

    PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)((QWORD)fileData + dos_header->e_lfanew);
    PIMAGE_OPTIONAL_HEADER64 optional_header = &(nt_headers->OptionalHeader);
    PIMAGE_DATA_DIRECTORY data_directory = optional_header->DataDirectory;

    time_t timestamp = nt_headers->FileHeader.TimeDateStamp;
    char* timestr = ctime(&timestamp);

    printf("\n[+] NT Headers\n");
    printf("\n\tSignature: %c%c\n", ((char *)&(nt_headers->Signature))[0], ((char *)&(nt_headers->Signature))[1]);

    // File Header struct-ception
    printf("\n[+] NT Headers -> File Header Struct\n");
    printf("\n\tMachine: \t\t\t%x\n", nt_headers->FileHeader.Machine);
    printf("\tNumber of Sections: \t\t%hu\n", nt_headers->FileHeader.NumberOfSections);
    printf("\tTime Date Stamp: \t\t0x%08lx, %s", nt_headers->FileHeader.TimeDateStamp, timestr);
    printf("\tPointer to Symbol Table: \t0x%lu\n", nt_headers->FileHeader.PointerToSymbolTable);
    printf("\tNumber of Symbols: \t\t0x%lx\n", nt_headers->FileHeader.NumberOfSymbols);
    printf("\tSize of Optional Header: \t0x%x\n", nt_headers->FileHeader.SizeOfOptionalHeader);
    printf("\tCharacteristics: \t\t0x%x\n", nt_headers->FileHeader.Characteristics);

    // Optional Header struct-ception
    printf("\n[+] NT Headers -> Optional Header Struct\n");
    printf("\n\tMagic Byte: \t\t\t\t0x%x\n", optional_header->Magic); //optional_header->Magic
    printf("\tMajor Linker Version: \t\t\t0x%x\n", optional_header->MajorLinkerVersion);
    printf("\tMinor Linker Version: \t\t\t0x%x\n", optional_header->MinorLinkerVersion);
    printf("\tSize of Code: \t\t\t\t0x%lx\n", optional_header->SizeOfCode);
    printf("\tSize of Initialized Data: \t\t0x%lx\n", optional_header->SizeOfInitializedData);
    printf("\tSize of Uninitialized Data: \t\t0x%lx\n", optional_header->SizeOfUninitializedData);
    printf("\tAddress of Entry Point: \t\t0x%lx\n", optional_header->AddressOfEntryPoint);
    printf("\tBase of Code: \t\t\t\t0x%lx\n", optional_header->BaseOfCode);
    printf("\tImage Base: \t\t\t\t0x%llx\n", optional_header->ImageBase);
    printf("\tSection Alignment: \t\t\t0x%lx\n", optional_header->SectionAlignment);
    printf("\tFile Alignment: \t\t\t0x%lx\n", optional_header->FileAlignment);
    printf("\tMajor Operating System Version: \t0x%x\n", optional_header->MajorOperatingSystemVersion);
    printf("\tMinor Operating System Version: \t0x%x\n", optional_header->MinorOperatingSystemVersion);
    printf("\tMajor Image Version: \t\t\t0x%x\n", optional_header->MajorImageVersion);
    printf("\tMinor Image Version: \t\t\t0x%x\n", optional_header->MinorImageVersion);
    printf("\tMajor Subsystem Version: \t\t0x%x\n", optional_header->MajorSubsystemVersion);
    printf("\tMinor Subsystem Version: \t\t0x%x\n", optional_header->MinorSubsystemVersion);
    printf("\tWin32 Version Value: \t\t\t0x%lx\n", optional_header->Win32VersionValue);
    printf("\tSize of Image: \t\t\t\t0x%lx\n", optional_header->SizeOfImage);
    printf("\tSize of Headers: \t\t\t0x%lx\n", optional_header->SizeOfHeaders);
    printf("\tChecksum: \t\t\t\t0x%lx\n", optional_header->CheckSum);
    printf("\tSubsystem: \t\t\t\t0x%x\n", optional_header->Subsystem);
    printf("\tDLL Characteristics: \t\t\t0x%x\n", optional_header->DllCharacteristics);
    printf("\tSize of Stack Reserve: \t\t\t0x%llx\n", optional_header->SizeOfStackReserve);
    printf("\tSize of Stack Commit: \t\t\t0x%llx\n", optional_header->SizeOfStackCommit);
    printf("\tSize of Heap Reserve: \t\t\t0x%llx\n", optional_header->SizeOfHeapReserve);
    printf("\tSize of Heap Commit: \t\t\t0x%llx\n", optional_header->SizeOfHeapCommit);
    printf("\tLoader Flags: \t\t\t\t0x%lx\n", optional_header->LoaderFlags);
    printf("\tNumber of RVA and Sizes: \t\t0x%lx\n", optional_header->NumberOfRvaAndSizes);

    printf("\n[+] Data Directory\n");
    printf("\n\tVirtual Address: \t0x%lx\n", data_directory->VirtualAddress);
    printf("\tSize: \t\t\t0x%lx\n", data_directory->Size);

    return 0;
}