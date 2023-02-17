# Command Line PE Parser - parsing executables (PE32, PE32+) in C

## Goal
To learn more about PE files by building a PE32/PE32+ compatible parser - done.

--- 

## Terminology 
### RVA (Relative Virtual Address)
The virtual address of an item in the file refers to the location in memory (virtual address space vs physical address space). 

The relative virtual address is the virtual address of the item relative to the base address of the image file / PE.

These concepts are quite important - one example where they come up are resource imports (like DLLs, e.g. VCRUNTIME.dll).

--- 

## Structure of a PE File

### 1) DOS Header

This is a 64-byte data structure at the very beginning of a PE file.
```c
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
```

Notes:
```
On e_lfanew, this represents the offset to the PE header from the end of the DOS header. In between is the DOS stub.
```

### 2) DOS Stub
This is a MS-DOS program.

### 3) PE/NT Header
Contains some of the most important information pertaining to the file.

This data structure differs between 32-bit and 64-bit variants.
32-bit: 
```c

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

typedef struct __IMAGE_NT_HEADERS32 {
    DWORD Signature;
    ___IMAGE_FILE_HEADER FileHeader;
    __IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} ___IMAGE_NT_HEADERS32;

```

64-bit: 
```c
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

typedef struct __IMAGE_NT_HEADERS64 {
    DWORD Signature;
    ___IMAGE_FILE_HEADER FileHeader;
    __IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} ___IMAGE_NT_HEADERS64;



```

### 4) Section Headers

  Each section header contains information about each section.
  
### 5) Sections

  Some common sections are .text, .data, .idata, .rsrc

### 6) Overlay 
Data appended at the end of the file (end of sections). 
