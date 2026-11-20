#include "pe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define FAIL(...) do { snprintf(err, errlen, __VA_ARGS__); goto fail; } while (0)

static uint16_t rd16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t rd64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }

void *pe_ptr(const pe_image *img, uint64_t rva, uint64_t len)
{
    if (rva > img->size || len > img->size - rva) return NULL;
    return img->base + rva;
}

const char *pe_str(const pe_image *img, uint64_t rva)
{
    if (rva >= img->size) return NULL;
    if (!memchr(img->base + rva, 0, img->size - rva)) return NULL;
    return (const char *)img->base + rva;
}

static int apply_relocs(pe_image *img, char *err, size_t errlen)
{
    uint64_t delta = (uint64_t)(uintptr_t)img->base - img->preferred_base;
    if (!delta) return 0;
    if (img->relocs_stripped)
        FAIL("image is not relocatable and its preferred base 0x%llx is unavailable",
             (unsigned long long)img->preferred_base);
    if (!img->reloc_size) return 0;                  /* fully position-independent image */
    uint8_t *p = pe_ptr(img, img->reloc_rva, img->reloc_size);
    if (!p) FAIL("relocation directory out of range");
    uint8_t *end = p + img->reloc_size;
    while (end - p >= 8) {
        uint32_t page = rd32(p), block = rd32(p + 4);
        if (block < 8 || block > (size_t)(end - p)) FAIL("bad relocation block");
        for (uint32_t i = 8; i + 2 <= block; i += 2) {
            uint16_t e = rd16(p + i);
            int type = e >> 12;
            if (type == 0) continue;                 /* IMAGE_REL_BASED_ABSOLUTE: padding */
            if (type != 10) FAIL("unsupported relocation type %d", type);
            uint8_t *slot = pe_ptr(img, (uint64_t)page + (e & 0xfff), 8);
            if (!slot) FAIL("relocation target out of range");
            uint64_t v = rd64(slot) + delta;         /* IMAGE_REL_BASED_DIR64 */
            memcpy(slot, &v, 8);
        }
        p += block;
    }
    return 0;
fail:
    return -1;
}

int pe_load(const char *path, pe_image *img, char *err, size_t errlen)
{
    uint8_t *file = NULL;
    memset(img, 0, sizeof *img);

    FILE *f = fopen(path, "rb");
    if (!f) FAIL("cannot open %s", path);
    fseek(f, 0, SEEK_END);
    long flen = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (flen < 0x40) { fclose(f); FAIL("file too small to be a PE image"); }
    file = malloc((size_t)flen);
    if (!file || fread(file, 1, (size_t)flen, f) != (size_t)flen) { fclose(f); FAIL("read error"); }
    fclose(f);
    size_t n = (size_t)flen;

    if (rd16(file) != 0x5a4d) FAIL("missing MZ signature");
    uint32_t pe = rd32(file + 0x3c);
    if (pe > n || n - pe < 24 + 112) FAIL("truncated PE header");
    if (rd32(file + pe) != 0x00004550) FAIL("missing PE signature");
    const uint8_t *coff = file + pe + 4;
    if (rd16(coff) != 0x8664) FAIL("not an x86-64 image (machine 0x%04x)", rd16(coff));
    int nsec = rd16(coff + 2);
    img->relocs_stripped = rd16(coff + 18) & 1;      /* IMAGE_FILE_RELOCS_STRIPPED */
    uint32_t optsize = rd16(coff + 16);
    const uint8_t *opt = coff + 20;
    if (optsize < 112 || n - (size_t)(opt - file) < optsize) FAIL("truncated optional header");
    if (rd16(opt) != 0x20b) FAIL("not a PE32+ image");
    if (nsec > PE_MAX_SECTIONS) FAIL("too many sections");

    img->entry_rva = rd32(opt + 16);
    img->preferred_base = rd64(opt + 24);
    uint32_t image_size = rd32(opt + 56);
    img->headers_size = rd32(opt + 60);
    uint32_t ndirs = rd32(opt + 108);
    if (ndirs > (optsize - 112) / 8) ndirs = (optsize - 112) / 8;
    if (ndirs > 1) { img->import_rva = rd32(opt + 112 + 8); img->import_size = rd32(opt + 112 + 12); }
    if (ndirs > 5) { img->reloc_rva = rd32(opt + 112 + 40); img->reloc_size = rd32(opt + 112 + 44); }

    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    if (!image_size || image_size > (1u << 31)) FAIL("implausible SizeOfImage");
    img->size = ((size_t)image_size + page - 1) & ~(page - 1);
    if (img->headers_size > n || img->headers_size > img->size) FAIL("bad SizeOfHeaders");

    /* Ask for the preferred base as a hint only; relocate if the kernel puts us elsewhere. */
    void *m = mmap((void *)(uintptr_t)img->preferred_base, img->size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
    if (m == MAP_FAILED) FAIL("cannot map %zu bytes for image", img->size);
    img->base = m;
    memcpy(img->base, file, img->headers_size);

    const uint8_t *sh = opt + optsize;
    if (n - (size_t)(sh - file) < (size_t)nsec * 40) FAIL("truncated section table");
    for (int i = 0; i < nsec; i++, sh += 40) {
        uint32_t vsize = rd32(sh + 8), rva = rd32(sh + 12);
        uint32_t rawsize = rd32(sh + 16), rawptr = rd32(sh + 20);
        uint32_t copy = rawsize < vsize || !vsize ? rawsize : vsize;
        if (!vsize) vsize = rawsize;
        if (!pe_ptr(img, rva, vsize)) FAIL("section %d lies outside the image", i);
        if (rawptr > n || copy > n - rawptr) FAIL("section %d raw data out of range", i);
        memcpy(img->base + rva, file + rawptr, copy);
        img->sec[i] = (pe_section){ rva, vsize, rd32(sh + 36) };
    }
    img->nsec = nsec;
    if (img->entry_rva >= img->size) FAIL("entry point outside the image");
    free(file);
    file = NULL;
    return apply_relocs(img, err, errlen);
fail:
    free(file);
    return -1;
}

int pe_protect(pe_image *img, char *err, size_t errlen)
{
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size_t hdr = (img->headers_size + page - 1) & ~(page - 1);
    if (hdr && mprotect(img->base, hdr, PROT_READ)) FAIL("mprotect(headers) failed");
    for (int i = 0; i < img->nsec; i++) {
        const pe_section *s = &img->sec[i];
        int prot = 0;
        if (s->chars & 0x40000000u) prot |= PROT_READ;
        if (s->chars & 0x80000000u) prot |= PROT_READ | PROT_WRITE;
        if (s->chars & 0x20000000u) prot |= PROT_READ | PROT_EXEC;
        if ((prot & PROT_WRITE) && (prot & PROT_EXEC))
            FAIL("section %d is writable and executable; refusing to map it", i);
        size_t start = s->rva & ~(page - 1);
        size_t end = ((size_t)s->rva + s->vsize + page - 1) & ~(page - 1);
        if (end > start && mprotect(img->base + start, end - start, prot))
            FAIL("mprotect(section %d) failed", i);
    }
    return 0;
fail:
    return -1;
}
