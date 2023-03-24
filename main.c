#include "Windows.h"
#include <stdio.h>
#include <time.h>

int main(int argc, char *argv[])
{
    PIMAGE_DOS_HEADER pDosHeader;
    HANDLE hFile, hFileMap;
    LPVOID lpFileBaseAddress;
    unsigned long long QWORD;

    /*

     // Uncomment when done debugging
    if (argc < 2)
    {
        printf("Usage: %s <Path to PE file>\n", argv[0]);
        return -1;
    }

     */

    // argv[1] originally under lpFileName, testing hard set file for debugging purposes
    hFile = CreateFileA("C:\\Users\\cody\\CLionProjects\\Another-PE-Parser\\cmake-build-debug\\Another_PE_Parser.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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

    // Get NT Headers using NT Headers start offset located in the DOS header added to the file base
    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((BYTE*)lpFileBaseAddress + pDosHeader->e_lfanew);

    // Get Optional Header. This is an extra step purely just to practice messing with the data, in future projects I'll skip directly to the Import Table.
    PIMAGE_OPTIONAL_HEADER64 pOptionalHeader = &pNtHeaders->OptionalHeader;

    // Get Import Table from Optional Header
    PIMAGE_DATA_DIRECTORY pDataDir = &pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    // Check if the Import Directory exists in the PE file. Had a huge headache with this, might remove at the end of this project.
    if (pDataDir->VirtualAddress == 0 || pDataDir->Size == 0)
    {
        printf("Data Directory Not Found!");
        // Import Directory not found
        return 1;
    }

    // Get Import Descriptor using it's RVA from the file base
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(lpFileBaseAddress + pDataDir->VirtualAddress);

    if (pImportDesc != NULL) {
        // use pImportDesc here
        printf("pImportDesc ISN'T NULL");
    }
    else {
        // handle null pointer
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
    //time_t timestamp = pNtHeaders->FileHeader.TimeDateStamp;
    //char* timestr = ctime(&timestamp);

    printf("\n[+] NT Headers\n");
    printf("\n\tSignature: %c%c\n", ((char *)&(pNtHeaders->Signature))[0], ((char *)&(pNtHeaders->Signature))[1]);

    // File Header struct-ception
    printf("\n[+] NT Headers -> File Header Struct\n");
    printf("\n\tMachine: \t\t\t%x\n", pNtHeaders->FileHeader.Machine);
    printf("\tNumber of Sections: \t\t%hu\n", pNtHeaders->FileHeader.NumberOfSections);
    printf("\tTime Date Stamp: \t\t0x%08lx", pNtHeaders->FileHeader.TimeDateStamp);
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
    printf("\n\tImport Directory Virtual Address: \t%lx\n", pDataDir->VirtualAddress);

    /*

    printf("\n[+] Import Table");
    if (pImportTable->VirtualAddress != 0)
        {
            while (pImportDesc->Name != 0)
            {
                char* pImportName = (char*)((BYTE*)lpFileBaseAddress + pImportDesc->Name);
                printf("\n\tName: \t%s", pImportName);
            }
        }
    printf("\n[+] testing \t%s", pImportDesc->Name);

    */

    // Parse the import table
    if (pDataDir->VirtualAddress != 0)
    {
        printf("\n[+] Import Table:\n");

        for (; pImportDesc->Name != 0; (PIMAGE_IMPORT_DESCRIPTOR)pImportDesc++)
        {
            PIMAGE_THUNK_DATA64 pThunk = (PIMAGE_THUNK_DATA64)((BYTE*)lpFileBaseAddress + pImportDesc->OriginalFirstThunk);
            printf("I'm here 1, can I print pImportDesc->OriginalFirstThunk and pThunk?: %lx %x\n", pImportDesc->OriginalFirstThunk, pThunk);

            // check that pThunk is not null and is properly aligned
            if (pThunk == NULL || ((DWORD_PTR)pThunk & 0x07) != 0)
            {
                printf("Invalid pThunk pointer!\n");
                break;
            }
            else
            {
                printf("((DWORD_PTR)pThunk & 0x07) Testing: %llx\n", ((DWORD_PTR)pThunk & 0x07));
            }
            printf("I'm here 2, printing pThunk->u1.Ordinal to debug loop: %llx\n", pThunk->u1.Ordinal);
            // iterate over the thunk data
            for (; pThunk->u1.AddressOfData != 0; pThunk++)
            {
                // check if the high-order bit is set (i.e., it's an ordinal value)
                if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                {
                    printf("Ordinal: %llx\n", pThunk->u1.Ordinal & 0xFFFF);
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)lpFileBaseAddress + pThunk->u1.AddressOfData);
                    printf("Function: %x\n", pImport->Name);
                    printf("AddressOfData Value: %llx\n", pThunk->u1.AddressOfData);
                }
            }
        }
    }
            /*
            while (pThunk->u1.AddressOfData != 0)
            {
                if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                {
                    printf("    Ordinal: 0x%llx\n", IMAGE_ORDINAL(pThunk->u1.Ordinal));
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)lpFileBaseAddress + pThunk->u1.AddressOfData);
                    printf("    Function: %s\n", pImportByName->Name);
                }

                pThunk++; // increment the pointer to next entry
            }
            pImportDesc++; // increment the pointer to next descriptor
        }
    }
    else {
        printf("Import table not found\n");
    }
*/

    return 0;
}