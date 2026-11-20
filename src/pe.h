/* PE32+ (x86-64) image loader. All offsets are bounds-checked: input files are untrusted. */
#ifndef XSE_PE_H
#define XSE_PE_H
#include <stddef.h>
#include <stdint.h>

#define PE_MAX_SECTIONS 96

typedef struct {
    uint32_t rva, vsize, chars;
} pe_section;

typedef struct {
    uint8_t *base;          /* where the image is mapped */
    size_t size;            /* SizeOfImage, page-rounded */
    uint64_t preferred_base;
    uint32_t entry_rva;
    uint32_t import_rva, import_size;
    uint32_t reloc_rva, reloc_size;
    uint32_t headers_size;
    int relocs_stripped;
    pe_section sec[PE_MAX_SECTIONS];
    int nsec;
} pe_image;

/* Maps the file read-write, copies sections, applies base relocations. */
int pe_load(const char *path, pe_image *img, char *err, size_t errlen);
/* Applies the final per-section page protections. Call after imports are bound. */
int pe_protect(pe_image *img, char *err, size_t errlen);
/* Returns a pointer to [rva, rva+len) inside the image, or NULL if out of range. */
void *pe_ptr(const pe_image *img, uint64_t rva, uint64_t len);
/* Returns a NUL-terminated string at rva, or NULL if it runs off the image. */
const char *pe_str(const pe_image *img, uint64_t rva);
#endif
