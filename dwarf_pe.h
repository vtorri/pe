#ifndef DWARF_PE_WIN32_H
#define DWARF_PE_WIN32_H

#include "dwarf_pe_private.h"
#include "dwarf_pe_map.h"
#ifndef _WIN32
# include "dwarf_pe_unix.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Dwarf_Pe_s Dwarf_Pe;

struct Dwarf_Pe_s
{
    Dwarf_Pe_Map map;
    const IMAGE_FILE_HEADER *file_header;
    const IMAGE_SECTION_HEADER *first_section;
    int sections_count;
    int is_64_bits : 1;
};

Dwarf_Pe *_dwarf_pe_begin_from_fd(int fd);

#ifdef _WIN32
Dwarf_Pe *_dwarf_pe_begin_from_file(LPCTSTR filename);
#else
Dwarf_Pe *_dwarf_pe_begin_from_file(const char *filename);
#endif

void _dwarf_pe_end(Dwarf_Pe *pe);

#ifdef __cplusplus
}
#endif

#endif /* DWARF_PE_WIN32_H */
