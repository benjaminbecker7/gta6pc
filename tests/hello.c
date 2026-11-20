/* Freestanding guest: prints through the Win32 API and checks the TEB self pointer. */
typedef unsigned int DWORD;
typedef void *HANDLE;
__declspec(dllimport) HANDLE GetStdHandle(DWORD);
__declspec(dllimport) int WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
__declspec(dllimport) void *HeapAlloc(HANDLE, DWORD, unsigned long long);
__declspec(dllimport) HANDLE GetProcessHeap(void);
__declspec(dllimport) void ExitProcess(DWORD);

const char *volatile msg = "hello from guest code\n";   /* absolute pointer in .data: needs a relocation */

static DWORD len(const char *s) { DWORD n = 0; while (s[n]) n++; return n; }

void start(void)
{
    HANDLE out = GetStdHandle((DWORD)-11);
    DWORD n;
    WriteFile(out, msg, len(msg), &n, 0);

    char *p = HeapAlloc(GetProcessHeap(), 8, 16);
    if (!p || p[15] != 0) ExitProcess(2);

#ifdef CHECK_TEB
    void *self, *teb;
    __asm__("movq %%gs:0x30, %0" : "=r"(self));
    __asm__("rdgsbase %0" : "=r"(teb));
    if (self != teb) ExitProcess(3);
    WriteFile(out, "teb ok\n", 7, &n, 0);
#endif
    ExitProcess(0);
}
