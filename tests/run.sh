#!/bin/sh
# Builds the guest test programs with clang + lld-link and runs them under xse.
set -eu
cd "$(dirname "$0")"
B=../build/tests; mkdir -p "$B"
XSE=../build/xse
CC="clang --target=x86_64-pc-windows-msvc -ffreestanding -fno-stack-protector -O1 -c"
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: expected [$3], got [$2]"; fail=1; fi; }

for d in kernel32 xgameruntime; do llvm-dlltool -m i386:x86-64 -d $d.def -l "$B/$d.lib"; done
link() { lld-link /nologo /entry:start /subsystem:console /nodefaultlib "$@" "$B/kernel32.lib" "$B/xgameruntime.lib"; }

TEB=""; [ "$(uname -s)" = Linux ] && TEB="-DCHECK_TEB -mfsgsbase"
$CC $TEB hello.c -o "$B/hello.obj"
$CC trap.c -o "$B/trap.obj"

link "$B/hello.obj" /out:"$B/hello.exe"
out=$($XSE "$B/hello.exe") && rc=0 || rc=$?
check "hello: exit code" "$rc" 0
check "hello: output" "$(echo "$out" | head -1)" "hello from guest code"
[ -n "$TEB" ] && check "hello: TEB via GS" "$(echo "$out" | tail -1)" "teb ok"

# Same program linked at a base outside user address space, forcing relocation.
link "$B/hello.obj" /out:"$B/hello_reloc.exe" /base:0x800000000000 /dynamicbase
out=$($XSE "$B/hello_reloc.exe") && rc=0 || rc=$?
check "relocated: exit code" "$rc" 0
moved=$($XSE -v "$B/hello_reloc.exe" 2>&1 | grep -c 'image at 0x800000000000 ' || true)
check "relocated: loaded away from preferred base" "$moved" 0
check "relocated: image has a relocation table" "$(llvm-readobj --coff-basereloc "$B/hello_reloc.exe" | grep -c DIR64)" 1
link "$B/hello.obj" /out:"$B/hello_fixed.exe" /base:0x800000000000 /fixed
$XSE "$B/hello_fixed.exe" 2>/dev/null && rc=0 || rc=$?
check "non-relocatable image at bad base rejected" "$rc" 65
check "relocated: output" "$(echo "$out" | head -1)" "hello from guest code"

link "$B/trap.obj" /out:"$B/trap.exe"
out=$($XSE "$B/trap.exe" 2>&1) && rc=0 || rc=$?
check "trap: exit code" "$rc" 70
check "trap: message" "$out" "xse: guest called unimplemented import xgameruntime.dll!XGameRuntimeInitialize"

printf 'MZ' > "$B/garbage.exe"; head -c 4096 /dev/urandom >> "$B/garbage.exe"
$XSE "$B/garbage.exe" 2>/dev/null && rc=0 || rc=$?
check "garbage file rejected" "$rc" 65
exit $fail
