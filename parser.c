// goal: disassemble PE32 files to x86-32 assembly code.
// potential future goal: port it using webassembly so we can leverage it on the web (via github?)

// notes: for some reason, there are an extra 16 bits (2 bytes) added for 64 bit I believe when PE32s don't work unless -16 from the offset calculation.
// very interesting - there's probably some extra memeory we are allocating in some struct that just doesn't match the size for PE32 vs PE32+
// #include <stdint.h>

// #include <iostream>

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

#define PE_FILE_MAGIC 0x5A4D

#define PE32_SIGNATURE 0x10B
#define PE32PLUS_SIGNATURE 0x20B

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef unsigned long long QWORD;
typedef unsigned long LONG;
typedef long long LONGLONG;
typedef unsigned long long ULONGLONG;


typedef struct __IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} ___IMAGE_FILE_HEADER;

typedef struct __IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} ___IMAGE_DATA_DIRECTORY;

typedef struct __IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    LONGLONG   ImageBase;
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
    ___IMAGE_DATA_DIRECTORY DataDirectory[16];
} __IMAGE_OPTIONAL_HEADER64;

typedef struct __IMAGE_OPTIONAL_HEADER32 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    DWORD       BaseOfData;
    DWORD   ImageBase;
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
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    ___IMAGE_DATA_DIRECTORY DataDirectory[16];
} __IMAGE_OPTIONAL_HEADER32;

typedef struct __IMAGE_NT_HEADERS64 {
    DWORD Signature;
    ___IMAGE_FILE_HEADER FileHeader;
    __IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} ___IMAGE_NT_HEADERS64;

typedef struct __IMAGE_NT_HEADERS32 {
    DWORD Signature;
    ___IMAGE_FILE_HEADER FileHeader;
    __IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} ___IMAGE_NT_HEADERS32;

typedef struct __DOS_HEADER {
    WORD   e_magic;
    WORD   e_cblp;
    WORD   e_cp;
    WORD   e_crlc;
    WORD   e_cparhdr;
    WORD   e_minalloc;
    WORD   e_maxalloc;
    WORD   e_ss;
    WORD   e_sp;
    WORD   e_csum;
    WORD   e_ip;
    WORD   e_cs;
    WORD   e_lfarlc;
    WORD   e_ovno;
    WORD   e_res[4];
    WORD   e_oemid;
    WORD   e_oeminfo;
    WORD   e_res2[10];
    LONG   e_lfanew;

} __DOS_HEADER;


typedef struct __IMAGE_SECTION_HEADER {
    BYTE    Name[8];
    union {
        DWORD   PhysicalAddress;
        DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} ___IMAGE_SECTION_HEADER;


typedef struct __IMAGE_IMPORT_DESCRIPTOR {
    DWORD   OriginalFirstThunk;
    DWORD   TimeDateStamp;
    DWORD   ForwarderChain;
    DWORD   Name;
    DWORD   FirstThunk;
} __IMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    BYTE   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

#include <stdio.h>
#include <stdlib.h>

long int convertRVAToAbsoluteOffset(unsigned long RVA, ___IMAGE_SECTION_HEADER peFileSectionHeaders[], int sizeOfSectionHeaders) {
    // first step is to determine which section has that address in it's range then calculate it from the 
    int sectionIndex = -1;
    
    for(int i = 0; i < sizeOfSectionHeaders; i++) {

        if( RVA >= peFileSectionHeaders[i].VirtualAddress && RVA < (peFileSectionHeaders[i].VirtualAddress +  peFileSectionHeaders[i].Misc.VirtualSize) ) {
            sectionIndex = i;
            break;
        }

    }

    printf("\nCorrect section: %s\n", peFileSectionHeaders[sectionIndex].Name);

    // once we determine the correct section, we need to calculate the offset
    long int offset = ( RVA - peFileSectionHeaders[sectionIndex].VirtualAddress ) + peFileSectionHeaders[sectionIndex].PointerToRawData;
    printf("Correct offset: %x\n", offset);

    return offset;

}

void parsePE32(FILE * peFile, __DOS_HEADER fileDOSHeader) {

    ___IMAGE_NT_HEADERS32 ntHeaders;

    fread(&ntHeaders, sizeof(___IMAGE_NT_HEADERS32), 1, peFile);

    printf("Entry Point: %x\n", ntHeaders.OptionalHeader.AddressOfEntryPoint);
    printf("Base of Code: %x\n", ntHeaders.OptionalHeader.BaseOfCode);
    printf("Base of Data: %x\n", ntHeaders.OptionalHeader.BaseOfData);
    printf("Image Base: %x\n", ntHeaders.OptionalHeader.ImageBase);
    printf("Section Alignment: %x\n", ntHeaders.OptionalHeader.SectionAlignment);
    printf("Checksum: %x\n", ntHeaders.OptionalHeader.CheckSum);
    

    ___IMAGE_SECTION_HEADER peFileSectionHeaders[ntHeaders.FileHeader.NumberOfSections];

    printf("\n======\nStart of PE Header: %x\n=====\n\n", fileDOSHeader.e_lfanew);
    printf("\n======\nOffset to First Section: %x\n=====\n\n", fileDOSHeader.e_lfanew+sizeof(___IMAGE_NT_HEADERS32));
    // printf("\n======\nCorrect Offset to First Section: %x\n=====\n\n", fileDOSHeader.e_lfanew+sizeof(___IMAGE_NT_HEADERS32));

    	for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
  
            int offset = (fileDOSHeader.e_lfanew + sizeof(___IMAGE_NT_HEADERS32) ) + (i * 40);

            printf("\nSection Offset: %X", offset);

            fseek(peFile, offset, SEEK_SET);
            fread(&peFileSectionHeaders[i], 40, 1, peFile);

        }

    printf("Size of DOS Header: %d\n", sizeof(fileDOSHeader));
    printf("Size of PE Header: %d\n",  sizeof(___IMAGE_NT_HEADERS32) );
    printf("Size of Section Headers: %d\n", sizeof(peFileSectionHeaders));
    printf("Size of Section Header: %d\n", sizeof(peFileSectionHeaders[0]));
    printf("Number of Sections: %d\n", ntHeaders.FileHeader.NumberOfSections);

    printf(" SECTION HEADERS:\n");
	printf(" ----------------\n\n");

	for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
		printf("   * %.8s:\n", peFileSectionHeaders[i].Name);
		printf("        VirtualAddress: 0x%X\n", peFileSectionHeaders[i].VirtualAddress);
		printf("        VirtualSize: 0x%X\n", peFileSectionHeaders[i].Misc.VirtualSize);
		printf("        PointerToRawData: 0x%X\n", peFileSectionHeaders[i].PointerToRawData);
		printf("        SizeOfRawData: 0x%X\n", peFileSectionHeaders[i].SizeOfRawData);
		printf("        Characteristics: 0x%X\n\n", peFileSectionHeaders[i].Characteristics);
	}

    // check if there are imports
    if(ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0x0) {

        printf("Address of Import Directory: %x\n", ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        printf("Size of Import Directory: %x", ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
        long int offset = convertRVAToAbsoluteOffset(ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, peFileSectionHeaders, ntHeaders.FileHeader.NumberOfSections);


        int importCount = 0;
        // calculate number of entries in import directory table
        while(1) {
              __IMAGE_IMPORT_DESCRIPTOR tmp;

            printf("\nImport offset: %x", offset +  (sizeof(__IMAGE_IMPORT_DESCRIPTOR) * importCount));

            fseek(peFile, offset +  (sizeof(__IMAGE_IMPORT_DESCRIPTOR) * importCount), 0);
            fread(&tmp, sizeof(__IMAGE_IMPORT_DESCRIPTOR), 1, peFile);

            if(tmp.Name == 0 && tmp.TimeDateStamp == 0) {
                break;    
            } 

            ++importCount;
        }

        __IMAGE_IMPORT_DESCRIPTOR imports[importCount];

        for(int i = 0; i < importCount; i++) {
        
            fseek(peFile, offset +  (sizeof(__IMAGE_IMPORT_DESCRIPTOR) * i), 0);
            fread(&imports[i], sizeof(__IMAGE_IMPORT_DESCRIPTOR), 1, peFile);

            printf("\nImport ILT RVA: %x\n", imports[i].OriginalFirstThunk);
            printf("\nImport ILT File Offset: %x\n",  convertRVAToAbsoluteOffset(imports[i].OriginalFirstThunk, peFileSectionHeaders, ntHeaders.FileHeader.NumberOfSections)  );
            
            

        }
    
    


    }




}

void parsePE32Plus(FILE * peFile, __DOS_HEADER fileDOSHeader) {
    

    ___IMAGE_NT_HEADERS64 ntHeaders;

    fread(&ntHeaders, sizeof(___IMAGE_NT_HEADERS64), 1, peFile);

    printf("Entry Point: %x\n", ntHeaders.OptionalHeader.AddressOfEntryPoint);
    printf("Base of Code: %x\n", ntHeaders.OptionalHeader.BaseOfCode);
    // printf("Base of Data: %x\n", ntHeaders.OptionalHeader.BaseOfData);
    printf("Image Base: %x\n", ntHeaders.OptionalHeader.ImageBase);



    ___IMAGE_SECTION_HEADER peFileSectionHeaders[ntHeaders.FileHeader.NumberOfSections];

    	for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
  
            int offset = (fileDOSHeader.e_lfanew + sizeof(___IMAGE_NT_HEADERS64) ) + (i * 40);

            printf("\nSection Offset: %X", offset);

            fseek(peFile, offset, SEEK_SET);
            fread(&peFileSectionHeaders[i], 40, 1, peFile);

        }

    printf("Size of DOS Header: %d\n", sizeof(fileDOSHeader));
    printf("Size of PE Header: %d\n",  sizeof(___IMAGE_NT_HEADERS64) );
    printf("Size of Section Headers: %d\n", sizeof(peFileSectionHeaders));
    printf("Size of Section Header: %d\n", sizeof(peFileSectionHeaders[0]));
    printf("Number of Sections: %d\n", ntHeaders.FileHeader.NumberOfSections);

    printf(" SECTION HEADERS:\n");
	printf(" ----------------\n\n");

	for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
		printf("   * %.8s:\n", peFileSectionHeaders[i].Name);
		printf("        VirtualAddress: 0x%X\n", peFileSectionHeaders[i].VirtualAddress);
		printf("        VirtualSize: 0x%X\n", peFileSectionHeaders[i].Misc.VirtualSize);
		printf("        PointerToRawData: 0x%X\n", peFileSectionHeaders[i].PointerToRawData);
		printf("        SizeOfRawData: 0x%X\n", peFileSectionHeaders[i].SizeOfRawData);
		printf("        Characteristics: 0x%X\n\n", peFileSectionHeaders[i].Characteristics);
	}


    // check if there are imports
    if(ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0x0) {

        printf("Address of Import Directory: %x\n", ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        printf("Size of Import Directory: %x", ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
        long int offset = convertRVAToAbsoluteOffset(ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, peFileSectionHeaders, ntHeaders.FileHeader.NumberOfSections);

        
    } 



}

void parseFile(char * filename) {

    FILE * peFile = fopen(filename, "rb");

    if(peFile == NULL) {
        exit(-1);
    }    

    __DOS_HEADER fileDOSHeader;
    
    fseek(peFile, 0, 0);
    fread(&fileDOSHeader, sizeof(__DOS_HEADER), 1, peFile);

    WORD PeFileType = 0;

    // QWORD s = 0;
    // fseek(peFile, 312, 0);
    // fread(&s, sizeof(long long ), 1, peFile);
    // printf("Image Base RAw: %x", s);

    fseek(peFile, (fileDOSHeader.e_lfanew + sizeof(DWORD) + sizeof(___IMAGE_FILE_HEADER)), SEEK_SET);
	fread(&PeFileType, sizeof(WORD), 1, peFile);

    printf("Type: %d (267 for PE32, 523 for PE32+) \n", PeFileType);


    printf(" DOS HEADER:\n");
	printf(" -----------\n\n");

	printf(" Magic: 0x%X\n", fileDOSHeader.e_magic);

    if (fileDOSHeader.e_magic != PE_FILE_MAGIC) {
        printf("Magic failed. Not valid PE FILE.");
        exit(1);
    }

	printf(" File address of new exe header: 0x%X\n", fileDOSHeader.e_lfanew);
    
    fseek(peFile, fileDOSHeader.e_lfanew, SEEK_SET);

    if(PeFileType == PE32_SIGNATURE) {
        parsePE32(peFile, fileDOSHeader);
    } else if(PeFileType == PE32PLUS_SIGNATURE) {
        parsePE32Plus(peFile, fileDOSHeader);
    } else {
        printf("sdf!!!");
    }

    fclose(peFile);

}

int main(int argc, char * argv[]) {
    
    parseFile(argv[1]);

    return 0;

}