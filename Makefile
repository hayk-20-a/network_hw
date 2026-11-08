
CC := gcc

TARGET := bin/inline_sec
SRC := src/inline_sec.c

CPPFLAGS := -Iinclude
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2 -g

PKG_CONFIG := pkg-config
PKG_CFLAGS := $(shell $(PKG_CONFIG) --cflags libnetfilter_queue openssl)
PKG_LIBS := $(shell $(PKG_CONFIG) --libs libnetfilter_queue openssl)

.PHONY: all clean

all: $(TARGET)

	$(TARGET): $(SRC)
	mkdir -p bin
	$(CC) $(CPPFLAGS) $(CFLAGS) $(PKG_CFLAGS) $< -o $@ $(PKG_LIBS)

	clean:
	rm -rf bin
