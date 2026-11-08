
CC := clang

OPENSSL_PREFIX := $(shell brew --prefix openssl@3)

CPPFLAGS := -Iinclude -I$(OPENSSL_PREFIX)/include
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2 -g

LDFLAGS := -L$(OPENSSL_PREFIX)/lib
LDLIBS := -lcrypto

TEST_CRYPTO := tests/test_crypto
TEST_HANDSHAKE := tests/test_handshake
TEST_PACKET := tests/test_packet

.PHONY: all test test-crypto test-handshake test-packet test-checksum clean

all: test

$(TEST_CRYPTO): tests/test_crypto.c src/crypto.c include/crypto.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_crypto.c src/crypto.c $(LDFLAGS) $(LDLIBS) -o $@

$(TEST_HANDSHAKE): tests/test_handshake.c src/handshake.c include/handshake.h include/crypto.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_handshake.c src/handshake.c $(LDFLAGS) $(LDLIBS) -o $@

$(TEST_PACKET): tests/test_packet.c src/packet.c include/packet.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_packet.c src/packet.c -o $@

test: test-crypto test-handshake test-packet test-checksum

test-crypto: $(TEST_CRYPTO)
	./$(TEST_CRYPTO)

test-handshake: $(TEST_HANDSHAKE)
	./$(TEST_HANDSHAKE)

test-packet: $(TEST_PACKET)
	./$(TEST_PACKET)

clean:
	rm -f $(TEST_CRYPTO) $(TEST_HANDSHAKE) $(TEST_PACKET) $(TEST_CHECKSUM)


TEST_CHECKSUM := tests/test_checksum

$(TEST_CHECKSUM): tests/test_checksum.c src/checksum.c src/packet.c include/checksum.h include/packet.h
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_checksum.c src/checksum.c src/packet.c -o $@

test-checksum: $(TEST_CHECKSUM)
	./$(TEST_CHECKSUM)