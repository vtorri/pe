
/*
 * Implement functions that maps the requested file in memory.
 * The file can be available from a filename or a file descriptor
 */

#include "dwarf_pe_private.h"
#include "dwarf_pe_map.h"

static int dwarf_pe_map_set_from_handle(Dwarf_Pe_Map *map)
{
    HANDLE fm;
    LARGE_INTEGER size;

    if (!GetFileSizeEx(map->file, &size)) {
        return 0;
    }

    map->size = size.QuadPart;
    fm = CreateFileMapping(map->file,
                           NULL, PAGE_READONLY,
                           0, 0, NULL);
    if (!fm) {
        return 0;
    }

    /* map file in READ only mode */
    map->base = MapViewOfFile(fm, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(fm);

    return (map->base != NULL);
}

int _dwarf_pe_map_set_from_file(Dwarf_Pe_Map *map, LPCTSTR filename)
{
    if (!filename) {
        return 0;
    }

    map->file = CreateFile(filename,
                           GENERIC_READ | FILE_READ_ATTRIBUTES,
                           0,
                           NULL,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
    if (map->file == INVALID_HANDLE_VALUE) {
        return 0;
    }

    map->from_fd = 0;

    return dwarf_pe_map_set_from_handle(map);
}

int _dwarf_pe_map_set_from_fd(Dwarf_Pe_Map *map, int fd)
{
    struct stat buf;

    if (fd < 0) {
        return 0;
    }

    if ((fstat(fd, &buf) < 0) ||
        !((buf.st_mode & _S_IFMT) == _S_IFREG)) {
        return 0;
    }

    map->file = (HANDLE)_get_osfhandle(fd);
    if ((map->file == INVALID_HANDLE_VALUE) &&
        (errno == EBADF)) {
        return 0;
    }

    map->from_fd = 1;

    return dwarf_pe_map_set_from_handle(map);
}

void _dwarf_pe_map_unset(Dwarf_Pe_Map *map)
{
    UnmapViewOfFile(map->base);
    if (!map->from_fd) {
        CloseHandle(map->file);
    }
}
