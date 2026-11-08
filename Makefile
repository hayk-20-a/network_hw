CC := clang

OPENSSL_PREFIX := $(shell brew --prefix openssl@3)

CPPFLAGS := -Iinclude -I$(OPENSSL_PREFIX)/include
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2 -g

LDFLAGS := -L$(OPENSSL_PREFIX)/lib
LDLIBS := -lcrypto

TEST_CRYPTO := tests/test_crypto
TEST_CRYPTO_SRC := tests/test_crypto.c src/crypto.c

.PHONY: all test clean

all: test

$(TEST_CRYPTO): $(TEST_CRYPTO_SRC) include/crypto.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(TEST_CRYPTO_SRC) $(LDFLAGS) $(LDLIBS) -o $@

test: $(TEST_CRYPTO)
	./$(TEST_CRYPTO)

clean:
	rm -f $(TEST_CRYPTO)