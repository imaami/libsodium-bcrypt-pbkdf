CC := gcc
CFLAGS := -std=gnu11 -Og -ggdb -pipe -Wall -Wextra

LIBSODIUM_CFLAGS = $(shell pkg-config --cflags libsodium)
LIBSODIUM_LIBS = $(shell pkg-config --libs libsodium)

LIBCRYPTO_CFLAGS = $(shell pkg-config --cflags libcrypto)
LIBCRYPTO_LIBS = $(shell pkg-config --libs libcrypto)

BIN := sodium-bcrypt-pbkdf-test
OBJ := sodium_bcrypt_pbkdf_test.o hexdump.o

INC = -I../include $(LIBSODIUM_CFLAGS) $(LIBCRYPTO_CFLAGS)
LIB = ../src/libsodium-bcrypt-pbkdf.a $(LIBSODIUM_LIBS) $(LIBCRYPTO_LIBS)

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) -o $@ $(CFLAGS) -s $^ $(LIB)

.PHONY: clean
clean:
	rm -f $(BIN) $(OBJ)

sodium_bcrypt_pbkdf_test.o: sodium_bcrypt_pbkdf_test.c
	$(CC) -o $@ -c $(CFLAGS) $(INC) $<

hexdump.o: hexdump.c
	$(CC) -o $@ -c $(CFLAGS) $<
