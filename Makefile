# Guest code is x86-64, so the host binary must be too (on Apple Silicon it runs under Rosetta 2).
CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra
ifeq ($(shell uname -s),Darwin)
CFLAGS += -arch x86_64
endif
SRC = src/main.c src/pe.c src/imports.c src/hle_kernel32.c

build/xse: $(SRC) src/pe.h src/hle.h
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ $(SRC)

test: build/xse
	sh tests/run.sh

clean:
	rm -rf build

.PHONY: test clean
