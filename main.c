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
    time_t timestamp = nt_headers->FileHeader.TimeDateStamp;
    char* timestr = ctime(&timestamp);

    printf("\n[+] NT Headers\n");
    printf("\n\tSignature: %c%c\n", ((char *)&(nt_headers->Signature))[0], ((char *)&(nt_headers->Signature))[1]);

    // struct-ception
    printf("\n[+] NT Headers -> File Header Struct\n");
    printf("\n\tMachine: \t\t\t%x\n", nt_headers->FileHeader.Machine);
    printf("\tNumber of Sections: \t\t%hu\n", nt_headers->FileHeader.NumberOfSections);
    printf("\tTime Date Stamp: \t\t%08x, %s", nt_headers->FileHeader.TimeDateStamp, timestr);
    printf("\tPointer to Symbol Table: \t0x%lu\n", nt_headers->FileHeader.PointerToSymbolTable);
    printf("\tNumber of Symbols: \t\t%x\n", nt_headers->FileHeader.NumberOfSymbols);
    printf("\tSize of Optional Header: \t%x\n", nt_headers->FileHeader.SizeOfOptionalHeader);
    printf("\tCharacteristics: \t\t%x\n", nt_headers->FileHeader.Characteristics);

    return 0;
}