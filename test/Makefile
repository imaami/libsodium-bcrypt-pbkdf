CC := gcc
CFLAGS := -std=gnu11 -Og -ggdb -pipe -Wall -Wextra

LIBSODIUM_CFLAGS = $(shell pkg-config --cflags libsodium)
LIBSODIUM_LIBS = $(shell pkg-config --libs libsodium)

LIBCRYPTO_CFLAGS = $(shell pkg-config --cflags libcrypto)
LIBCRYPTO_LIBS = $(shell pkg-config --libs libcrypto)

# If you don't have explicit_bzero() you can run 'make HAVE_EXPLICIT_BZERO=0'
# instead of commenting out this line.
HAVE_EXPLICIT_BZERO := 1

BIN := sodium-bcrypt-pbkdf-test
OBJ := sodium_bcrypt_pbkdf_test.o sshkey.o hexdump.o

LIB = ../src/libsodium-bcrypt-pbkdf.a $(LIBSODIUM_LIBS) $(LIBCRYPTO_LIBS)

override SSHKEY_CFLAGS = -I../include -I../src $(LIBSODIUM_CFLAGS) $(LIBCRYPTO_CFLAGS)

ifeq ($(strip $(HAVE_EXPLICIT_BZERO)),1)
override SSHKEY_CFLAGS += -DHAVE_EXPLICIT_BZERO=1
endif

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) -o $@ $(CFLAGS) $^ $(LIB)

.PHONY: clean
clean:
	rm -f $(BIN) $(OBJ)

sodium_bcrypt_pbkdf_test.o: sodium_bcrypt_pbkdf_test.c
	$(CC) -o $@ -c $(CFLAGS) $(LIBSODIUM_CFLAGS) $<

sshkey.o: sshkey.c
	$(CC) -o $@ -c $(CFLAGS) $(SSHKEY_CFLAGS) $<

hexdump.o: hexdump.c
	$(CC) -o $@ -c $(CFLAGS) $<
