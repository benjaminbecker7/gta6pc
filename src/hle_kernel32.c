/* Host implementations of the Win32 base API subset the guest can call.
 * Xbox titles import these through several DLL names (kernel32, kernelbase,
 * api-ms-win-* API sets), so lookup is by function name only. */
#include "hle.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

typedef uint32_t DWORD;
typedef int32_t BOOL;
typedef void *HANDLE;

#define H_STDIN  ((HANDLE)(uintptr_t)0x10)
#define H_HEAP   ((HANDLE)(uintptr_t)0x20)
#define ERROR_INVALID_HANDLE 6
#define ERROR_NOT_ENOUGH_MEMORY 8
#define ERROR_INVALID_PARAMETER 87

static __thread DWORD last_error;
static const pe_image *g_img;

static int handle_fd(HANDLE h)
{
    uintptr_t v = (uintptr_t)h;
    return v >= 0x10 && v <= 0x12 ? (int)(v - 0x10) : -1;
}

static MSABI HANDLE GetStdHandle(DWORD id)
{
    switch ((int32_t)id) {
    case -10: return H_STDIN;
    case -11: return (HANDLE)(uintptr_t)0x11;
    case -12: return (HANDLE)(uintptr_t)0x12;
    }
    last_error = ERROR_INVALID_HANDLE;
    return (HANDLE)(intptr_t)-1;
}

static MSABI BOOL WriteFile(HANDLE h, const void *buf, DWORD len, DWORD *written, void *overlapped)
{
    (void)overlapped;
    int fd = handle_fd(h);
    if (fd < 1) { last_error = ERROR_INVALID_HANDLE; return 0; }
    ssize_t n = write(fd, buf, len);
    if (written) *written = n < 0 ? 0 : (DWORD)n;
    return n >= 0;
}

static MSABI BOOL WriteConsoleA(HANDLE h, const void *buf, DWORD len, DWORD *written, void *reserved)
{
    return WriteFile(h, buf, len, written, reserved);
}

static MSABI void ExitProcess(DWORD code) { _exit((int)(code & 0xff)); }
static MSABI DWORD GetLastError(void) { return last_error; }
static MSABI void SetLastError(DWORD e) { last_error = e; }
static MSABI DWORD GetCurrentProcessId(void) { return (DWORD)getpid(); }
static MSABI DWORD GetCurrentThreadId(void) { return (DWORD)getpid(); }
static MSABI BOOL IsDebuggerPresent(void) { return 0; }
static MSABI void OutputDebugStringA(const char *s) { if (s) (void)!write(2, s, strlen(s)); }
static MSABI HANDLE GetProcessHeap(void) { return H_HEAP; }

static MSABI void *HeapAlloc(HANDLE heap, DWORD flags, size_t size)
{
    (void)heap;
    void *p = (flags & 8) ? calloc(1, size ? size : 1) : malloc(size ? size : 1);  /* HEAP_ZERO_MEMORY */
    if (!p) last_error = ERROR_NOT_ENOUGH_MEMORY;
    return p;
}

static MSABI BOOL HeapFree(HANDLE heap, DWORD flags, void *p)
{
    (void)heap; (void)flags;
    free(p);
    return 1;
}

/* VirtualFree(MEM_RELEASE) passes no size, so reservations are tracked here. */
static struct { void *addr; size_t size; } vmap[256];

static MSABI void *VirtualAlloc(void *addr, size_t size, DWORD type, DWORD protect)
{
    (void)type;
    if (!size) { last_error = ERROR_INVALID_PARAMETER; return NULL; }
    if (protect & 0xf0) { last_error = ERROR_INVALID_PARAMETER; return NULL; }  /* no executable allocations yet */
    for (int i = 0; i < 256; i++) {
        if (vmap[i].addr) continue;
        void *p = mmap(addr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (p == MAP_FAILED) break;
        vmap[i].addr = p;
        vmap[i].size = size;
        return p;
    }
    last_error = ERROR_NOT_ENOUGH_MEMORY;
    return NULL;
}

static MSABI BOOL VirtualFree(void *addr, size_t size, DWORD type)
{
    (void)size; (void)type;
    for (int i = 0; i < 256; i++) {
        if (!addr || vmap[i].addr != addr) continue;
        munmap(addr, vmap[i].size);
        vmap[i].addr = NULL;
        return 1;
    }
    last_error = ERROR_INVALID_PARAMETER;
    return 0;
}

static uint64_t mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static MSABI BOOL QueryPerformanceCounter(int64_t *out) { *out = (int64_t)(mono_ns() / 100); return 1; }
static MSABI BOOL QueryPerformanceFrequency(int64_t *out) { *out = 10000000; return 1; }
static MSABI uint64_t GetTickCount64(void) { return mono_ns() / 1000000; }

static MSABI void GetSystemTimeAsFileTime(uint64_t *ft)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    /* 100 ns ticks since 1601-01-01 */
    *ft = ((uint64_t)ts.tv_sec + 11644473600ull) * 10000000ull + (uint64_t)ts.tv_nsec / 100;
}

static MSABI void Sleep(DWORD ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static MSABI HANDLE GetModuleHandleW(const void *name)
{
    if (name) { last_error = 126; return NULL; }   /* ERROR_MOD_NOT_FOUND */
    return g_img ? g_img->base : NULL;
}

static const struct { const char *name; void *fn; } table[] = {
#define F(x) { #x, (void *)x }
    F(GetStdHandle), F(WriteFile), F(WriteConsoleA), F(ExitProcess), F(GetLastError),
    F(SetLastError), F(GetCurrentProcessId), F(GetCurrentThreadId), F(IsDebuggerPresent),
    F(OutputDebugStringA), F(GetProcessHeap), F(HeapAlloc), F(HeapFree), F(VirtualAlloc),
    F(VirtualFree), F(QueryPerformanceCounter), F(QueryPerformanceFrequency),
    F(GetTickCount64), F(GetSystemTimeAsFileTime), F(Sleep), F(GetModuleHandleW),
    { "GetModuleHandleA", (void *)GetModuleHandleW },
#undef F
};

void *hle_lookup(const char *dll, const char *name)
{
    (void)dll;
    for (size_t i = 0; i < sizeof table / sizeof *table; i++)
        if (!strcmp(table[i].name, name)) return table[i].fn;
    return NULL;
}

/* ---- thread/process environment block ---- */
#ifdef __linux__
#include <sys/syscall.h>
#define ARCH_SET_GS 0x1001
#endif

int teb_install(const pe_image *img)
{
    g_img = img;
#ifdef __linux__
    /* Windows x64 code reaches the TEB through the GS segment; glibc leaves GS unused. */
    uint64_t *teb = calloc(1, 0x2000), *peb = calloc(1, 0x1000);
    if (!teb || !peb) return -1;
    peb[0x10 / 8] = (uintptr_t)img->base;     /* PEB.ImageBaseAddress */
    teb[0x30 / 8] = (uintptr_t)teb;           /* TEB.Self */
    teb[0x40 / 8] = (uint64_t)getpid();       /* ClientId.UniqueProcess */
    teb[0x48 / 8] = (uint64_t)getpid();       /* ClientId.UniqueThread */
    teb[0x60 / 8] = (uintptr_t)peb;           /* TEB.ProcessEnvironmentBlock */
    return (int)syscall(SYS_arch_prctl, ARCH_SET_GS, teb);
#else
    /* macOS reserves GS for its own thread-local storage; guests that read the TEB
     * directly will not work there until this is solved (see README). */
    return 1;
#endif
}
