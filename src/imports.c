#include "hle.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define FAIL(...) do { snprintf(err, errlen, __VA_ARGS__); return -1; } while (0)
#define THUNK_SIZE 32

static MSABI void trap(const char *name, const char *dll)
{
    fprintf(stderr, "xse: guest called unimplemented import %s!%s\n", dll, name);
    _exit(EXIT_UNIMPLEMENTED);
}

/* mov rcx, name; mov rdx, dll; mov rax, trap; jmp rax */
static void emit_thunk(uint8_t *p, const char *name, const char *dll)
{
    uint64_t a = (uintptr_t)name, b = (uintptr_t)dll, c = (uintptr_t)trap;
    p[0] = 0x48; p[1] = 0xb9; memcpy(p + 2, &a, 8);
    p[10] = 0x48; p[11] = 0xba; memcpy(p + 12, &b, 8);
    p[20] = 0x48; p[21] = 0xb8; memcpy(p + 22, &c, 8);
    p[30] = 0xff; p[31] = 0xe0;
}

int imports_bind(pe_image *img, int verbose, char *err, size_t errlen)
{
    if (!img->import_size) return 0;

    /* Pass 1 counts the thunks we need; pass 2 fills the import address table. */
    uint8_t *thunks = NULL;
    size_t nthunks = 0, tsize = 0;
    for (int pass = 0; pass < 2; pass++) {
        size_t used = 0;
        for (uint64_t d = img->import_rva;; d += 20) {
            uint32_t *desc = pe_ptr(img, d, 20);
            if (!desc) FAIL("import directory out of range");
            uint32_t ilt = desc[0], name_rva = desc[3], iat = desc[4];
            if (!name_rva && !iat) break;
            const char *dll = pe_str(img, name_rva);
            if (!dll) FAIL("bad import DLL name");
            if (!ilt) ilt = iat;
            for (uint64_t i = 0;; i++) {
                uint64_t *look = pe_ptr(img, ilt + i * 8, 8);
                uint64_t *slot = pe_ptr(img, iat + i * 8, 8);
                if (!look || !slot) FAIL("import thunk out of range (%s)", dll);
                uint64_t v = *look;
                if (!v) break;
                static char ordbuf[32];
                const char *name;
                void *fn = NULL;
                if (v >> 63) {
                    snprintf(ordbuf, sizeof ordbuf, "#%u", (unsigned)(v & 0xffff));
                    name = pass ? strdup(ordbuf) : ordbuf;
                } else {
                    name = pe_str(img, v + 2);
                    if (!name) FAIL("bad import name (%s)", dll);
                    fn = hle_lookup(dll, name);
                }
                if (!pass) { if (!fn) nthunks++; continue; }
                if (!fn) {
                    fn = thunks + used * THUNK_SIZE;
                    emit_thunk(fn, name, dll);
                    used++;
                    if (verbose) fprintf(stderr, "xse: stub     %s!%s\n", dll, name);
                } else if (verbose) {
                    fprintf(stderr, "xse: bound    %s!%s\n", dll, name);
                }
                uint64_t addr = (uintptr_t)fn;
                memcpy(slot, &addr, 8);
            }
        }
        if (!pass && nthunks) {
            tsize = nthunks * THUNK_SIZE;
            thunks = mmap(NULL, tsize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
            if (thunks == MAP_FAILED) FAIL("cannot allocate import thunks");
        }
    }
    /* Thunks are written first and only then made executable (never W+X at once). */
    if (thunks && mprotect(thunks, tsize, PROT_READ | PROT_EXEC)) FAIL("mprotect(thunks) failed");
    return 0;
}
