#ifndef DWARF_PE_UNIX_H
#define DWARF_PE_UNIX_H

#define _WIN64

#define IMAGE_DOS_SIGNATURE 0x5a4d
#define IMAGE_NT_SIGNATURE 0x00004550

/*
 * Data types
 * see https://msdn.microsoft.com/en-us/library/windows/desktop/aa383751(v=vs.85).aspx
 */
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef int LONG;
typedef unsigned int DWORD;
typedef unsigned long long ULONGLONG; /* 64 bits unsigned integer */
#if defined(_WIN64)
 typedef long long LONG_PTR;
#else
 typedef long LONG_PTR;
#endif
#if defined(_WIN64)
 typedef unsigned long long ULONG_PTR;
#else
 typedef unsigned long ULONG_PTR;
#endif

#define FIELD_OFFSET(type,field) ((LONG)(LONG_PTR)&(((type *)0)->field))

/*
 * IMAGE_FILE_HEADER
 * see https://msdn.microsoft.com/fr-fr/library/windows/desktop/ms680313(v=vs.85).aspx
 */
typedef struct
{
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} IMAGE_FILE_HEADER;

/*
 * IMAGE_DATA_DIRECTORY
 * see https://msdn.microsoft.com/fr-fr/library/windows/desktop/ms680305(v=vs.85).aspx
 */
typedef struct
{
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY;

/*
 * IMAGE_OPTIONAL_HEADER
 * see https://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
 */
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct
{
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    DWORD BaseOfData;
    DWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    DWORD SizeOfStackReserve;
    DWORD SizeOfStackCommit;
    DWORD SizeOfHeapReserve;
    DWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32;

typedef struct
{
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    ULONGLONG ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64;

/*
 * IMAGE_NT_HEADERS
 * see https://msdn.microsoft.com/fr-fr/library/windows/desktop/ms680336(v=vs.85).aspx
 */

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC 0x107

typedef struct
{
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct
{
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

#ifdef _WIN64
    typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS;
    typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
#else
    typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS;
    typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;
#endif

/*
 * IMAGE_SECTION_HEADER
 * see https://msdn.microsoft.com/en-us/library/windows/desktop/ms680341(v=vs.85).aspx
 */

#define IMAGE_FIRST_SECTION(ntheader) ((PIMAGE_SECTION_HEADER) ((ULONG_PTR)ntheader + FIELD_OFFSET(IMAGE_NT_HEADERS,OptionalHeader) + ((PIMAGE_NT_HEADERS)(ntheader))->FileHeader.SizeOfOptionalHeader))

#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct
{
    BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#define IMAGE_SCN_SCALE_INDEX            0x00000001 // Tls index is scaled
#define IMAGE_SCN_TYPE_NO_PAD            0x00000008 // Reserved.
#define IMAGE_SCN_CNT_CODE               0x00000020 // Section contains code.
#define IMAGE_SCN_CNT_INITIALIZED_DATA   0x00000040 // Section contains initialized data.
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080 // Section contains uninitialized data.

#define IMAGE_SCN_LNK_OTHER              0x00000100 // Reserved.
#define IMAGE_SCN_LNK_INFO               0x00000200 // Section contains comments or some other type of information.
#define IMAGE_SCN_LNK_REMOVE             0x00000800 // Section contents will not become part of image.
#define IMAGE_SCN_LNK_COMDAT             0x00001000 // Section contents comdat.
#define IMAGE_SCN_NO_DEFER_SPEC_EXC      0x00004000 // Reset speculative exceptions handling bits in the TLB entries for this section.
#define IMAGE_SCN_MEM_FARDATA            0x00008000
#define IMAGE_SCN_MEM_PURGEABLE          0x00020000
#define IMAGE_SCN_MEM_LOCKED             0x00040000
#define IMAGE_SCN_MEM_PRELOAD            0x00080000

#define IMAGE_SCN_ALIGN_1BYTES           0x00100000 //
#define IMAGE_SCN_ALIGN_2BYTES           0x00200000 //
#define IMAGE_SCN_ALIGN_4BYTES           0x00300000 //
#define IMAGE_SCN_ALIGN_8BYTES           0x00400000 //
#define IMAGE_SCN_ALIGN_16BYTES          0x00500000 // Default alignment if no others are specified.
#define IMAGE_SCN_ALIGN_32BYTES          0x00600000 //
#define IMAGE_SCN_ALIGN_64BYTES          0x00700000 //
#define IMAGE_SCN_ALIGN_128BYTES         0x00800000 //
#define IMAGE_SCN_ALIGN_256BYTES         0x00900000 //
#define IMAGE_SCN_ALIGN_512BYTES         0x00A00000 //
#define IMAGE_SCN_ALIGN_1024BYTES        0x00B00000 //
#define IMAGE_SCN_ALIGN_2048BYTES        0x00C00000 //
#define IMAGE_SCN_ALIGN_4096BYTES        0x00D00000 //
#define IMAGE_SCN_ALIGN_8192BYTES        0x00E00000 //

#define IMAGE_SCN_ALIGN_MASK             0x00F00000
#define IMAGE_SCN_LNK_NRELOC_OVFL        0x01000000 // Section contains extended relocations.
#define IMAGE_SCN_MEM_DISCARDABLE        0x02000000 // Section can be discarded.
#define IMAGE_SCN_MEM_NOT_CACHED         0x04000000 // Section is not cachable.
#define IMAGE_SCN_MEM_NOT_PAGED          0x08000000 // Section is not pageable.
#define IMAGE_SCN_MEM_SHARED             0x10000000 // Section is shareable.
#define IMAGE_SCN_MEM_EXECUTE            0x20000000 // Section is executable.
#define IMAGE_SCN_MEM_READ               0x40000000 // Section is readable.
#define IMAGE_SCN_MEM_WRITE              0x80000000 // Section is writeable.

#define IMAGE_SIZEOF_SYMBOL 18

#endif /* DWARFPE_UNIX_H */
