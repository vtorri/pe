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

typedef struct _Dwarf_Pe_s Dwarf_Pe;

struct _Dwarf_Pe_s
{
    Dwarf_Pe_Map map;
    IMAGE_NT_HEADERS *nt_header; /**< The NT header address */
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
