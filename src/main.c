#include "hle.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    int verbose = 0;
    const char *path = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v")) verbose = 1;
        else if (!path) path = argv[i];
        else path = "";
    }
    if (!path || !*path) {
        fprintf(stderr, "usage: xse [-v] <image.exe>\n");
        return 64;
    }

    static pe_image img;
    char err[256];
    if (pe_load(path, &img, err, sizeof err) || imports_bind(&img, verbose, err, sizeof err) ||
        pe_protect(&img, err, sizeof err)) {
        fprintf(stderr, "xse: %s: %s\n", path, err);
        return 65;
    }
    int teb = teb_install(&img);
    if (teb < 0) { fprintf(stderr, "xse: cannot install guest TEB\n"); return 71; }
    if (teb > 0 && verbose) fprintf(stderr, "xse: no guest TEB on this host\n");
    if (verbose)
        fprintf(stderr, "xse: image at %p (preferred 0x%llx), entry %p\n", (void *)img.base,
                (unsigned long long)img.preferred_base, (void *)(img.base + img.entry_rva));

    MSABI uint32_t (*entry)(void) = (MSABI uint32_t (*)(void))(img.base + img.entry_rva);
    return (int)(entry() & 0xff);
}
