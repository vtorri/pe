#ifndef DWARF_PE_WIN32_MAP_H
#define DWARF_PE_WIN32_MAP_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _Dwarf_Pe_Map_s Dwarf_Pe_Map;

struct _Dwarf_Pe_Map_s
{
    HANDLE file;
    unsigned char *base;
    long long size;
    unsigned int from_fd : 1;
};

int _dwarf_pe_map_set_from_file(Dwarf_Pe_Map *map, LPCTSTR filename);

int _dwarf_pe_map_set_from_fd(Dwarf_Pe_Map *map, int fd);

void _dwarf_pe_map_unset(Dwarf_Pe_Map *map);

#ifdef __cplusplus
}
#endif

#endif /* DWARF_PE_WIN32_MAP_H */
