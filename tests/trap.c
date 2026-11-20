/* Guest that calls an Xbox runtime API the emulator does not implement yet. */
__declspec(dllimport) int XGameRuntimeInitialize(void);
__declspec(dllimport) void ExitProcess(unsigned int);
void start(void) { ExitProcess(XGameRuntimeInitialize() ? 1 : 0); }
