BIN := libsodium-bcrypt-pbkdf.a
OBJ := sodium_bcrypt_pbkdf.o openbsd-compat/bcrypt_pbkdf.o openbsd-compat/blowfish.o

all: $(BIN)

$(BIN): $(OBJ)
	$(AR) rcs $@ $^

sodium_bcrypt_pbkdf.o: sodium_bcrypt_pbkdf.c
	$(CC) -o $@ -c $(CFLAGS) $<

openbsd-compat/bcrypt_pbkdf.o: openbsd-compat/bcrypt_pbkdf.c
	$(CC) -o $@ -c $(CFLAGS) -I. $(shell pkg-config --cflags libsodium) $<

openbsd-compat/blowfish.o: openbsd-compat/blowfish.c
	$(CC) -o $@ -c $(CFLAGS) -I. $<

.PHONY: clean
clean:
	rm -f $(BIN) $(OBJ)
