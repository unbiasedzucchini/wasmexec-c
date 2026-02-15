CC      ?= gcc
CFLAGS  := -O2 -Wall -Wextra -Wno-unused-parameter -std=c11
CFLAGS  += $(shell pkg-config --cflags libmicrohttpd sqlite3)
LDFLAGS := $(shell pkg-config --libs libmicrohttpd sqlite3) -lpthread -lm

# wasm3 vendored sources
W3_SRC := $(wildcard wasm3/m3_*.c)
W3_OBJ := $(W3_SRC:.c=.o)

all: server

wasm3/%.o: wasm3/%.c
	$(CC) $(CFLAGS) -Wno-unused-function -Wno-sign-compare -c -o $@ $<

server.o: server.c
	$(CC) $(CFLAGS) -c -o $@ $<

server: server.o $(W3_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f server server.o wasm3/*.o

# Test wasm module (requires wat2wasm from wabt)
test/echo.wasm: test/echo.wat
	wat2wasm $< -o $@

.PHONY: all clean
