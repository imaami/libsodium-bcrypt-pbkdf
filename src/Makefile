BIN := libsodium-bcrypt-pbkdf.a
OBJ := sodium_bcrypt_pbkdf.o openbsd-compat/bcrypt_pbkdf.o openbsd-compat/blowfish.o

override OPENBSD_COMPAT_CFLAGS := $(CFLAGS) -I.
override BCRYPT_PBKDF_CFLAGS = $(shell pkg-config --cflags libsodium)

ifeq ($(strip $(HAVE_EXPLICIT_BZERO)),1)
override BCRYPT_PBKDF_CFLAGS += -DHAVE_EXPLICIT_BZERO=1
endif

all: $(BIN)

$(BIN): $(OBJ)
	$(AR) rcs $@ $^

sodium_bcrypt_pbkdf.o: sodium_bcrypt_pbkdf.c
	$(CC) -o $@ -c $(CFLAGS) $<

openbsd-compat/bcrypt_pbkdf.o: openbsd-compat/bcrypt_pbkdf.c
	$(CC) -o $@ -c $(OPENBSD_COMPAT_CFLAGS) $(BCRYPT_PBKDF_CFLAGS) $<

openbsd-compat/blowfish.o: openbsd-compat/blowfish.c
	$(CC) -o $@ -c $(OPENBSD_COMPAT_CFLAGS) $<

.PHONY: clean
clean:
	rm -f $(BIN) $(OBJ)
