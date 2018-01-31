BIN := libsodium-bcrypt-pbkdf.a
OBJ := openbsd-compat/bcrypt_pbkdf.o openbsd-compat/blowfish.o
CLN := $(BIN) $(OBJ) sodium_bcrypt_pbkdf.o

ifeq ($(strip $(NO_REDEFINE_SYM)),1)
OBJ += sodium_bcrypt_pbkdf.o
endif

override OPENBSD_COMPAT_CFLAGS := $(CFLAGS) -I.
override BCRYPT_PBKDF_CFLAGS = $(shell pkg-config --cflags libsodium)

ifeq ($(strip $(HAVE_EXPLICIT_BZERO)),1)
override BCRYPT_PBKDF_CFLAGS += -DHAVE_EXPLICIT_BZERO=1
endif

all: $(BIN)

$(BIN): $(OBJ)
	$(AR) rcs $@ $^

ifeq ($(strip $(NO_REDEFINE_SYM)),1)
sodium_bcrypt_pbkdf.o: sodium_bcrypt_pbkdf.c
	$(CC) -o $@ -c $(CFLAGS) $<
endif

openbsd-compat/bcrypt_pbkdf.o: openbsd-compat/bcrypt_pbkdf.c
	$(CC) -o $@ -c $(OPENBSD_COMPAT_CFLAGS) $(BCRYPT_PBKDF_CFLAGS) $<
ifneq ($(strip $(NO_REDEFINE_SYM)),1)
	$(OBJCOPY) --redefine-sym bcrypt_pbkdf=sodium_bcrypt_pbkdf $@
endif

openbsd-compat/blowfish.o: openbsd-compat/blowfish.c
	$(CC) -o $@ -c $(OPENBSD_COMPAT_CFLAGS) $<

.PHONY: clean
clean:
	rm -f $(CLN)
