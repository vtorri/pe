
/*
 * Implement functions that open a file from filename or file
 * descriptor
 */
/* references:
 * [1] https://msdn.microsoft.com/library/windows/desktop/ms680547(v=vs.85).aspx
 * [2] https://msdn.microsoft.com/en-us/library/ms809762.aspx
 */

#include <stdlib.h> /* calloc() */
#include <stdio.h> /* FIXME */

#include "dwarf_pe.h"

static int dwarf_pe_check(Dwarf_Pe *pe)
{
    IMAGE_NT_HEADERS *nt_header;
    IMAGE_FILE_HEADER *file_header;
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
     * The NT header is located at address 0x3c, see [1],
     * so size must be at least 0x40.
     */
    if (pe->map.size < 0x40) {
        return 0;
    }

    nt_address = *((DWORD *)(pe->map.base + 0x3c));
    if (pe->map.size < nt_address) {
        return 0;
    }

    nt_header = (IMAGE_NT_HEADERS *)(pe->map.base + nt_address);

    /*
     * Description :
     *
     * The file must contain the NT HEADER from that address, see [1],
     * otherwise it is probably a 16 bits DOS module, which we do not
     * care. So the size must be at least, in addition to nt_address:
     * - a DWORD (the NT signature)
     * - an IMAGE_FILE_HEADER structure
     * - an IMAGE_OPTIONAL_HEADER 32 or 64 which size is given by the
     * SizeOfOptionalHeader field of IMAGE_FILE_HEADER
     *
     * Just after the NT header are the section eaders (see [1]).
     */

    /*
     * The NT header must begin with the "PE\0\0" string
     * which is 0x00004550, called IMAGE_NT_SIGNATURE (see [1], [2]).
     * The type of this signature is a DWORD.
     */
    if (pe->map.size < (nt_address + sizeof(DWORD))) {
        return 0;
    }

    if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    /*
    * The NT signature is followed by a an IMAGE_FILE_HEADER
    */
    if (pe->map.size < (nt_address +
                        sizeof(DWORD) +
                        sizeof(IMAGE_FILE_HEADER))) {
        return 0;
    }
    file_header = (IMAGE_FILE_HEADER *)(pe->map.base + nt_address + sizeof(DWORD));

    /*
     * Get the architecture on wich the PE file has been created.
     * Get it from the Machine field of file_header
     */
    if (file_header->Machine == IMAGE_FILE_MACHINE_I386) {
        pe->is_64_bits = 0;
    } else if ((file_header->Machine == IMAGE_FILE_MACHINE_IA64) ||
               (file_header->Machine == IMAGE_FILE_MACHINE_AMD64)) {
        pe->is_64_bits = 1;
    } else {
        return 0;
    }

    /*
     * Get the number of sections (limited to 96, see [1])
     */
    if (file_header->NumberOfSections > 96) {
        return 0;
    }

    pe->sections_count = file_header->NumberOfSections + 1;

    /*
     * The section headers are just after the NT header
     */
    pe->first_section = (const IMAGE_SECTION_HEADER *)
        (pe->map.base +
         nt_address +
         sizeof(DWORD) +
         sizeof(IMAGE_FILE_HEADER) +
         file_header->SizeOfOptionalHeader);

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
