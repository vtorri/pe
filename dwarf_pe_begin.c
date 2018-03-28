
/*
 * Implement functions that open a file from filename or file
 * descriptor
 */
/* references:
 * [1] https://msdn.microsoft.com/library/windows/desktop/ms680547(v=vs.85).aspx
 * [2] https://msdn.microsoft.com/en-us/library/ms809762.aspx
 */

#include "dwarf_pe.h"

static int dwarf_pe_check(Dwarf_Pe *pe)
{
    DWORD nt_address;

    /*
     * The file must contain the DOS HEADER,
     * which is 64 bytes long, see [1].
     */
    if (pe->map.size < 64) {
        return 0;
    }

    /*
     * The header must begin with the "MZ" string
     * (Mark Zbikowski, the DOS architect),
     * which is 0x5A4D, called IMAGE_DOS_SIGNATURE.
     * It is 2 bytes long
     */
    if (*((WORD *)pe->map.base) != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    /*
     * The NT header is located at address 0x3c, see [1]
     */
    nt_address = *((DWORD *)(pe->map.base + 0x3c));

    /*
     * The file must contain the NT HEADER from that address, see [1],
     * otherwise it is probably a 16 bits DOS module,
     * which we do not care.
     */
    if (pe->map.size < nt_address + sizeof(IMAGE_NT_HEADERS)) {
        return 0;
    }

    pe->nt_header = (IMAGE_NT_HEADERS *)(pe->map.base + nt_address);
    /*
     * The header must begin with the "PE\0\0" string
     * which is 0x00004550, called IMAGE_NT_SIGNATURE (see [1], [2]).
     */
    if (pe->nt_header->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    return 1;
}

Dwarf_Pe *_dwarf_pe_begin_from_fd(int fd)
{
    Dwarf_Pe *pe;

    pe = (Dwarf_Pe *)calloc(1, sizeof(Dwarf_Pe));
    if (!pe) {
        return NULL;
    }

    _dwarf_pe_map_set_from_fd(&pe->map, fd);

    if (!dwarf_pe_check(pe)) {
        _dwarf_pe_map_unset(&pe->map);
        free(pe);

        return NULL;
    }

    /* from now, we suppose that the file is a valid PE file */

    return pe;
}

#ifdef _WIN32

Dwarf_Pe *_dwarf_pe_begin_from_file(LPCTSTR filename)
{
    Dwarf_Pe *pe;

    pe = (Dwarf_Pe *)calloc(1, sizeof(Dwarf_Pe));
    if (!pe) {
        return NULL;
    }

    if (!_dwarf_pe_map_set_from_file(&pe->map, filename)) {
        free(pe);

        return NULL;
    }

    if (!dwarf_pe_check(pe)) {
        _dwarf_pe_map_unset(&pe->map);
        free(pe);

        return NULL;
    }

    /* from now, we suppose that the file is a valid PE file */

    return pe;
}

#else

Dwarf_Pe *_dwarf_pe_begin_from_file(const char *filename)
{
    Dwarf_Pe *pe;

    pe = (Dwarf_Pe *)calloc(1, sizeof(Dwarf_Pe));
    if (!pe) {
        return NULL;
    }

    if (!_dwarf_pe_map_set_from_file(&pe->map, filename)) {
        free(pe);

        return NULL;
    }

    if (!dwarf_pe_check(pe)) {
        _dwarf_pe_map_unset(&pe->map);
        free(pe);

        return NULL;
    }

    /* from now, we suppose that the file is a valid PE file */

    return pe;
}

#endif

void
_dwarf_pe_end(Dwarf_Pe *pe)
{
    if (!pe) {
        return;
    }

    _dwarf_pe_map_unset(&pe->map);
    free(pe);
}
