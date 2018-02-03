AR := ar
CC := gcc
OBJCOPY := objcopy
CFLAGS := -std=gnu11 -Og -ggdb -pipe -Wall -Wextra

LIBSODIUM_CFLAGS = $(shell pkg-config --cflags libsodium)

# Set to 1 if you don't have objcopy with --redefine-sym capability, in which
# case a wrapper function will be built instead of redefining an existing one.
NO_REDEFINE_SYM := 0

# If you don't have explicit_bzero() you can run 'make HAVE_EXPLICIT_BZERO=0'
# instead of commenting out this line.
HAVE_EXPLICIT_BZERO := 1

BIN := libsodium-bcrypt-pbkdf.a
OBJ := openbsd-compat/bcrypt_pbkdf.o openbsd-compat/blowfish.o
CLN := $(BIN) $(OBJ) sodium_bcrypt_pbkdf.o

ifeq ($(strip $(NO_REDEFINE_SYM)),1)
OBJ += sodium_bcrypt_pbkdf.o
endif

override OPENBSD_COMPAT_CFLAGS := $(CFLAGS) -I.
override BCRYPT_PBKDF_CFLAGS = $(LIBSODIUM_CFLAGS)

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
