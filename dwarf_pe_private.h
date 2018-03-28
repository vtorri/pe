#ifndef DWARF_PE_PRIVATE_H
#define DWARF_PE_PRIVATE_H

#ifdef _WIN32

# include <stdlib.h>
# include <sys/stat.h>
# include <errno.h>

# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
# undef WIN32_LEAN_AND_MEAN

# include <io.h> /* _get_osfhandle() */

#else

# include <fcntl.h> /* open() */
# include <unistd.h> /* close() */
# include <sys/mman.h> /* mmap() */
# include <sys/stat.h> /* fstat() */

#endif

#endif /* DWARF_PE_PRIVATE_H */
