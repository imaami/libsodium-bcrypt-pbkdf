AR := ar
CC := gcc
OBJCOPY := objcopy
CFLAGS := -std=gnu11 -Og -ggdb -pipe -Wall -Wextra

LIBSODIUM_CFLAGS = $(shell pkg-config --cflags libsodium)

# Set to 1 if you don't have objcopy with --redefine-sym capability, in which
# case a wrapper function will be built instead of redefining an existing one.
NO_REDEFINE_SYM := 0

override BIN := libsodium-bcrypt-pbkdf.a
override OBJ := openbsd-compat/bcrypt_pbkdf.o openbsd-compat/blowfish.o
override CLN := $(BIN) $(OBJ) sodium_bcrypt_pbkdf.o

ifeq ($(strip $(NO_REDEFINE_SYM)),1)
override OBJ += sodium_bcrypt_pbkdf.o
endif

override OPENBSD_COMPAT_CFLAGS := $(CFLAGS) -I.

all: $(BIN)

$(BIN): $(OBJ)
	$(AR) rcs $@ $^

ifeq ($(strip $(NO_REDEFINE_SYM)),1)
sodium_bcrypt_pbkdf.o: sodium_bcrypt_pbkdf.c
	$(CC) -o $@ -fPIC -c $(CFLAGS) $<
endif

openbsd-compat/bcrypt_pbkdf.o: openbsd-compat/bcrypt_pbkdf.c check-explicit-bzero
	$(CC) -o $@ -fPIC -c $(OPENBSD_COMPAT_CFLAGS) $(LIBSODIUM_CFLAGS) $(EXPLICIT_BZERO_CFLAGS) $<
ifneq ($(strip $(NO_REDEFINE_SYM)),1)
	$(OBJCOPY) --redefine-sym bcrypt_pbkdf=sodium_bcrypt_pbkdf $@
endif

openbsd-compat/blowfish.o: openbsd-compat/blowfish.c
	$(CC) -o $@ -fPIC -c $(OPENBSD_COMPAT_CFLAGS) $<

.PHONY: clean
clean:
	rm -f $(CLN)

# Run 'make HAVE_EXPLICIT_BZERO=0' to force using libsodium's sodium_memzero().
.PHONY: check-explicit-bzero
check-explicit-bzero:
	$(eval override EXPLICIT_BZERO_CFLAGS:=$(shell\
	  V='$(strip $(HAVE_EXPLICIT_BZERO))';\
	  if [ x"$$V" = 'x1' ]; then\
	    echo -n -DHAVE_EXPLICIT_BZERO=1;\
	  elif [ x"$$V" != 'x0' ]; then\
	    echo -n 'Checking for explicit_bzero... ' >&2;\
	    echo '#include <string.h>\nint main(void){int i;explicit_bzero(&i,sizeof(i));return i;}'\
	    | $(CC) -xc -O0 -o/dev/null - 2>/dev/null; V=$$?;\
	    if [ x"$$V" = 'x0' ]; then\
	      echo 'yes' >&2;\
	      echo -n -DHAVE_EXPLICIT_BZERO=1;\
	    else\
	      echo 'no' >&2;\
	    fi;\
	  fi))
