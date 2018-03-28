
/*
 * Implement functions that maps the requested file in memory.
 * The file can be available from a filename or a file descriptor
 */

#include "dwarf_pe_private.h"
#include "dwarf_pe_map.h"

int _dwarf_pe_map_set_from_fd(Dwarf_Pe_Map *map, int fd)
{
    struct stat buf;

    if (fd < 0) {
        return 0;
    }

    if ((fstat(fd, &buf) < 0) ||
        !((buf.st_mode & S_IFMT) == S_IFREG)) {
        return 0;
    }

    map->file = fd;
    map->size = buf.st_size;
    map->base = mmap(NULL, map->size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map->base == MAP_FAILED) {
        return 0;
    }

    map->from_fd = 1;

    return 1;
}

int
_dwarf_pe_map_set_from_file(Dwarf_Pe_Map *map, const char *filename)
{
    int fd;
    int ret;

    if (!filename || !*filename) {
        return 0;
    }

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        return 0;
    }

    ret = _dwarf_pe_map_set_from_fd(map, fd);
    map->from_fd = 0;

    return ret;
}

void
_dwarf_pe_map_unset(Dwarf_Pe_Map *map)
{
    munmap(map->base, map->size);
    if (!map->from_fd) {
        close(map->file);
    }
}
