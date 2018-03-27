#ifndef DWARF_PE_WIN32_H
#define DWARF_PE_WIN32_H

#include "dwarf_pe_win32_private.h"
#include "dwarf_pe_win32_map.h"

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

Dwarf_Pe *_dwarf_pe_begin_from_file(LPCTSTR filename);

void _dwarf_pe_end(Dwarf_Pe *pe);

#ifdef __cplusplus
}
#endif

#endif /* DWARF_PE_WIN32_H */
