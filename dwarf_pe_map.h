#ifndef DWARF_PE_MAP_H
#define DWARF_PE_MAP_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
typedef HANDLE Dwarf_Fd;
#else
typedef int Dwarf_Fd;
#endif

typedef struct Dwarf_Pe_Map_s Dwarf_Pe_Map;

struct Dwarf_Pe_Map_s
{
    Dwarf_Fd file;
    unsigned char *base;
    long long size;
    unsigned int from_fd : 1;
};

#ifdef _WIN32
int _dwarf_pe_map_set_from_file(Dwarf_Pe_Map *map, LPCTSTR filename);
#else
int _dwarf_pe_map_set_from_file(Dwarf_Pe_Map *map, const char *filename);
#endif

int _dwarf_pe_map_set_from_fd(Dwarf_Pe_Map *map, int fd);

void _dwarf_pe_map_unset(Dwarf_Pe_Map *map);

#ifdef __cplusplus
}
#endif

#endif /* DWARF_PE_MAP_H */
