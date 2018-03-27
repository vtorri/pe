#ifndef DWARF_PE_WIN32_PRIVATE_H
#define DWARF_PE_WIN32_PRIVATE_H

#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN

#include <io.h> /* _get_osfhandle() */

#endif /* DWARF_PE_WIN32_PRIVATE_H */
