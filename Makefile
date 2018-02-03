AR := ar
CC := gcc
OBJCOPY := objcopy
CFLAGS := -std=gnu11 -Og -ggdb -pipe -Wall -Wextra

LIBSODIUM_CFLAGS = $(shell pkg-config --cflags libsodium)
LIBSODIUM_LIBS = $(shell pkg-config --libs libsodium)

LIBCRYPTO_CFLAGS = $(shell pkg-config --cflags libcrypto)
LIBCRYPTO_LIBS = $(shell pkg-config --libs libcrypto)

# Set to 1 if you don't have objcopy with --redefine-sym capability, in which
# case a wrapper function will be built instead of redefining an existing one.
NO_REDEFINE_SYM := 0

# If you don't have explicit_bzero() you can run 'make HAVE_EXPLICIT_BZERO=0'
# instead of commenting out this line.
HAVE_EXPLICIT_BZERO := 1

all: lib test

.PHONY: lib
lib:
	+$(MAKE) -C src \
		AR="$(AR)" \
		CC="$(CC)" \
		OBJCOPY="$(OBJCOPY)" \
		CFLAGS="$(CFLAGS)" \
		LIBSODIUM_CFLAGS="$(LIBSODIUM_CFLAGS)" \
		NO_REDEFINE_SYM="$(NO_REDEFINE_SYM)" \
		HAVE_EXPLICIT_BZERO="$(HAVE_EXPLICIT_BZERO)"

.PHONY: test
test: lib
	+$(MAKE) -C test \
		CC="$(CC)" \
		CFLAGS="$(CFLAGS)" \
		LIBSODIUM_CFLAGS="$(LIBSODIUM_CFLAGS)" \
		LIBCRYPTO_CFLAGS="$(LIBCRYPTO_CFLAGS)" \
		LIBSODIUM_LIBS="$(LIBSODIUM_LIBS)" \
		LIBCRYPTO_LIBS="$(LIBCRYPTO_LIBS)"

clean: clean-lib clean-test

.PHONY: clean-lib
clean-lib:
	+$(MAKE) -C src clean

.PHONY: clean-test
clean-test:
	+$(MAKE) -C test clean
