/* High-level emulation of the guest's system libraries. */
#ifndef XSE_HLE_H
#define XSE_HLE_H
#include "pe.h"

#define MSABI __attribute__((ms_abi))
#define EXIT_UNIMPLEMENTED 70   /* guest called an import we have no implementation for */

/* Returns the host implementation of a guest import, or NULL. */
void *hle_lookup(const char *dll, const char *name);
/* Binds every import of the image: implemented ones to host code, the rest to trap thunks. */
int imports_bind(pe_image *img, int verbose, char *err, size_t errlen);
/* Installs a minimal thread/process environment block for the guest. */
int teb_install(const pe_image *img);
#endif
