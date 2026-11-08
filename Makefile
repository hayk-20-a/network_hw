
CC := clang

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
OPENSSL_PREFIX := $(shell brew --prefix openssl@3)
CPPFLAGS := -Iinclude -I$(OPENSSL_PREFIX)/include
LDFLAGS := -L$(OPENSSL_PREFIX)/lib
LDLIBS := -lcrypto
endif

ifeq ($(UNAME_S),Linux)
CPPFLAGS := -Iinclude $(shell pkg-config --cflags libnetfilter_queue openssl)
LDFLAGS := $(shell pkg-config --libs-only-L libnetfilter_queue openssl)
LDLIBS := $(shell pkg-config --libs libnetfilter_queue openssl)
endif

CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2 -g

TEST_CRYPTO := tests/test_crypto
TEST_HANDSHAKE := tests/test_handshake
TEST_PACKET := tests/test_packet
TEST_SESSION := tests/test_session
TEST_SEQMAP := tests/test_seqmap
TEST_CHECKSUM := tests/test_checksum
TEST_FRAME := tests/test_frame

GATEWAY := inline_sec

GATEWAY_SOURCES := \
	src/inline_sec.c \
	src/gateway.c \
	src/control.c \
	src/frame.c \
	src/session.c \
	src/handshake.c \
	src/crypto.c \
	src/packet.c \
	src/checksum.c \
	src/seqmap.c \
	src/control.c \
	src/control_socket.c \

.PHONY: all test gateway test-crypto test-handshake test-packet \
	test-checksum test-seqmap test-session test-frame clean

all: test

gateway: $(GATEWAY)

$(GATEWAY): $(GATEWAY_SOURCES)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(GATEWAY_SOURCES) $(LDFLAGS) $(LDLIBS) -o $@

$(TEST_CRYPTO): tests/test_crypto.c src/crypto.c include/crypto.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_crypto.c src/crypto.c $(LDFLAGS) $(LDLIBS) -o $@

$(TEST_HANDSHAKE): tests/test_handshake.c src/handshake.c include/handshake.h include/crypto.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_handshake.c src/handshake.c $(LDFLAGS) $(LDLIBS) -o $@

$(TEST_PACKET): tests/test_packet.c src/packet.c include/packet.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_packet.c src/packet.c -o $@

$(TEST_CHECKSUM): tests/test_checksum.c src/checksum.c src/packet.c include/checksum.h include/packet.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_checksum.c src/checksum.c src/packet.c -o $@

$(TEST_SEQMAP): tests/test_seqmap.c src/seqmap.c include/seqmap.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_seqmap.c src/seqmap.c -o $@

$(TEST_SESSION): tests/test_session.c src/session.c src/handshake.c include/session.h include/handshake.h include/crypto.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_session.c src/session.c src/handshake.c $(LDFLAGS) $(LDLIBS) -o $@

$(TEST_FRAME): tests/test_frame.c src/frame.c src/session.c src/handshake.c src/crypto.c include/frame.h include/session.h include/handshake.h include/crypto.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_frame.c src/frame.c src/session.c src/handshake.c src/crypto.c $(LDFLAGS) $(LDLIBS) -o $@

test: test-crypto test-handshake test-packet test-checksum test-seqmap test-session test-frame

test-crypto: $(TEST_CRYPTO)
	./$(TEST_CRYPTO)

test-handshake: $(TEST_HANDSHAKE)
	./$(TEST_HANDSHAKE)

test-packet: $(TEST_PACKET)
	./$(TEST_PACKET)

test-checksum: $(TEST_CHECKSUM)
	./$(TEST_CHECKSUM)

test-seqmap: $(TEST_SEQMAP)
	./$(TEST_SEQMAP)

test-session: $(TEST_SESSION)
	./$(TEST_SESSION)

test-frame: $(TEST_FRAME)
	./$(TEST_FRAME)

clean:
	rm -f $(TEST_CRYPTO) $(TEST_HANDSHAKE) $(TEST_PACKET) \
	      $(TEST_CHECKSUM) $(TEST_SEQMAP) $(TEST_SESSION) \
	      $(TEST_FRAME) $(GATEWAY)
