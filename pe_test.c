
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "dwarf_pe.h"

static char pe_section_name[9];

static const char *
pe_section_string_table_get(const Dwarf_Pe *pe)
{
    if (!pe->nt_header->FileHeader.PointerToSymbolTable  ||
        !pe->nt_header->FileHeader.NumberOfSymbols * IMAGE_SIZEOF_SYMBOL)
        return NULL;

    return (const char *)(pe->map.base + pe->nt_header->FileHeader.PointerToSymbolTable + pe->nt_header->FileHeader.NumberOfSymbols * IMAGE_SIZEOF_SYMBOL);
}

static const char *
pe_section_name_get(const Dwarf_Pe *pe, const IMAGE_SECTION_HEADER *sh)
{
    if (sh->Name[0] == '/')
        return pe_section_string_table_get(pe) + atoi((const char*)sh->Name + 1);
    else
    {
        memcpy(pe_section_name, sh->Name, 8);
        pe_section_name[8] = '\0';
        return pe_section_name;
    }
}

#ifdef _WIN32
# define FMT_DWD "%lu"
# define FMT_DWDX "%lx"
# define FMT_DWD8X "%08lx"
# define FMT_LL16X "%016I64x"
#else
# define FMT_DWD "%u"
# define FMT_DWDX "%x"
# define FMT_DWD8X "%08x"
# define FMT_LL16X "%016llx"
#endif

void
pe_sections_display(Dwarf_Pe *pe)
{
    IMAGE_SECTION_HEADER *iter;
    WORD i;

    iter = IMAGE_FIRST_SECTION(pe->nt_header);
    for (i = 0; i < pe->nt_header->FileHeader.NumberOfSections; i++, iter++)
    {
        printf("Section header #%u\n", i);
        printf("  field                type    value\n");
        printf("  Name[8]              BYTE    %c%c%c%c%c%c%c%c", iter->Name[0], iter->Name[1], iter->Name[2], iter->Name[3], iter->Name[4], iter->Name[5], iter->Name[6], iter->Name[7]);
        if (iter->Name[0] == '/')
            printf(" (%s)", pe_section_name_get(pe, iter));
        printf("\n");
        printf("  VirtualSize          DWORD   0x" FMT_DWDX "\n", iter->Misc.VirtualSize);
        printf("  VirtualAddress       DWORD   0x" FMT_DWDX "\n", iter->VirtualAddress);
        printf("  SizeOfRawData        DWORD   0x" FMT_DWDX "\n", iter->SizeOfRawData);
        printf("  PointerToRawData     DWORD   0x" FMT_DWDX "\n", iter->PointerToRawData);
        printf("  PointerToRelocations DWORD   0x" FMT_DWDX "\n", iter->PointerToRelocations);
        printf("  PointerToLinenumbers DWORD   0x" FMT_DWDX "\n", iter->PointerToLinenumbers);
        printf("  NumberOfRelocations  WORD    0x%x\n", iter->NumberOfRelocations);
        printf("  NumberOfLinenumbers  WORD    0x%x\n", iter->NumberOfLinenumbers);
        printf("  Characteristics      DWORD   0x" FMT_DWDX " (%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u)\n",
               iter->Characteristics,
               (iter->Characteristics & IMAGE_SCN_SCALE_INDEX) == IMAGE_SCN_SCALE_INDEX,
               (iter->Characteristics & IMAGE_SCN_TYPE_NO_PAD) == IMAGE_SCN_TYPE_NO_PAD,
               (iter->Characteristics & IMAGE_SCN_CNT_CODE) == IMAGE_SCN_CNT_CODE,
               (iter->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) == IMAGE_SCN_CNT_INITIALIZED_DATA,
               (iter->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) == IMAGE_SCN_CNT_UNINITIALIZED_DATA,
               (iter->Characteristics & IMAGE_SCN_LNK_OTHER) == IMAGE_SCN_LNK_OTHER,
               (iter->Characteristics & IMAGE_SCN_LNK_INFO) == IMAGE_SCN_LNK_INFO,
               (iter->Characteristics & IMAGE_SCN_LNK_REMOVE) == IMAGE_SCN_LNK_REMOVE,
               (iter->Characteristics & IMAGE_SCN_LNK_COMDAT) == IMAGE_SCN_LNK_COMDAT,
               (iter->Characteristics & IMAGE_SCN_NO_DEFER_SPEC_EXC) == IMAGE_SCN_NO_DEFER_SPEC_EXC,
               (iter->Characteristics & IMAGE_SCN_MEM_FARDATA) == IMAGE_SCN_MEM_FARDATA,
               (iter->Characteristics & IMAGE_SCN_MEM_PURGEABLE) == IMAGE_SCN_MEM_PURGEABLE,
               (iter->Characteristics & IMAGE_SCN_MEM_LOCKED) == IMAGE_SCN_MEM_LOCKED,
               (iter->Characteristics & IMAGE_SCN_MEM_PRELOAD) == IMAGE_SCN_MEM_PRELOAD,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_1BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_2BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_4BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_8BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_16BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_32BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_64BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_128BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_256BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_512BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_1024BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_2048BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_4096BYTES,
               (iter->Characteristics & 0x00ff0000) == IMAGE_SCN_ALIGN_8192BYTES,
               (iter->Characteristics & IMAGE_SCN_ALIGN_MASK) == IMAGE_SCN_ALIGN_MASK,
               (iter->Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL) == IMAGE_SCN_LNK_NRELOC_OVFL,
               (iter->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == IMAGE_SCN_MEM_DISCARDABLE,
               (iter->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) == IMAGE_SCN_MEM_NOT_CACHED,
               (iter->Characteristics & IMAGE_SCN_MEM_NOT_PAGED) == IMAGE_SCN_MEM_NOT_PAGED,
               (iter->Characteristics & IMAGE_SCN_MEM_SHARED) == IMAGE_SCN_MEM_SHARED,
               (iter->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE,
               (iter->Characteristics & IMAGE_SCN_MEM_READ) == IMAGE_SCN_MEM_READ,
               (iter->Characteristics & IMAGE_SCN_MEM_WRITE) == IMAGE_SCN_MEM_WRITE);
        if (i != (pe->nt_header->FileHeader.NumberOfSections - 1))
            printf("\n");
    }
}

int main(int argc, char *argv[])
{
#if 0
    Dwarf_Pe_Map map;
    int ret;

    if (argc < 2)
    {
        printf("Usage : %s file\n", argv[0]);
        return 0;
    }

    memset(&map, 0, sizeof(Pe_Map));

    ret = pe_map_set_from_file(&map, argv[1]);
    printf(" ret : %d\n", ret);

    printf(" %c%c\n", ((unsigned char *)map.base)[0], ((unsigned char *)map.base)[1]);

    pe_map_unset(&map);

    memset(&map, 0, sizeof(Pe_Map));
    ret = pe_map_set_from_fd(&map, 23156465);
    printf(" ret : %d\n", ret);

    {
        int fd;

        fd = open(argv[1], O_RDONLY, S_IREAD);
        memset(&map, 0, sizeof(Pe_Map));
        ret = pe_map_set_from_fd(&map, fd);
        printf(" ret : %d\n", ret);

        printf(" %c%c\n", ((unsigned char *)map.base)[0], ((unsigned char *)map.base)[1]);

        pe_map_unset(&map);
        close(fd);
    }
#endif

    Dwarf_Pe *pe;

    if (argc < 2)
    {
        printf("Usage : %s file\n", argv[0]);
        return 0;
    }

    pe = _dwarf_pe_begin_from_file(argv[1]);
    if (!pe)
    {
        printf("not a valid PE file\n");
        return 1;
    }

    pe_sections_display(pe);

    _dwarf_pe_end(pe);

    return 0;
}
