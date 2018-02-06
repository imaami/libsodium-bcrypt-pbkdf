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

all: lib test

.PHONY: lib
lib: check-explicit-bzero
	+$(MAKE) -C src \
		AR="$(AR)" \
		CC="$(CC)" \
		OBJCOPY="$(OBJCOPY)" \
		CFLAGS="$(CFLAGS)" \
		LIBSODIUM_CFLAGS="$(LIBSODIUM_CFLAGS)" \
		NO_REDEFINE_SYM="$(NO_REDEFINE_SYM)" \
		HAVE_EXPLICIT_BZERO="$(HAVE_EXPLICIT_BZERO)"

.PHONY: test
test: lib check-explicit-bzero
	+$(MAKE) -C test \
		CC="$(CC)" \
		CFLAGS="$(CFLAGS)" \
		LIBSODIUM_CFLAGS="$(LIBSODIUM_CFLAGS)" \
		LIBCRYPTO_CFLAGS="$(LIBCRYPTO_CFLAGS)" \
		LIBSODIUM_LIBS="$(LIBSODIUM_LIBS)" \
		LIBCRYPTO_LIBS="$(LIBCRYPTO_LIBS)" \
		HAVE_EXPLICIT_BZERO="$(HAVE_EXPLICIT_BZERO)"

clean: clean-lib clean-test

.PHONY: clean-lib
clean-lib:
	+$(MAKE) -C src clean

.PHONY: clean-test
clean-test:
	+$(MAKE) -C test clean

# Run 'make HAVE_EXPLICIT_BZERO=0' to force using libsodium's sodium_memzero().
.PHONY: check-explicit-bzero
check-explicit-bzero:
	$(eval override HAVE_EXPLICIT_BZERO:=$(shell\
	  V='$(strip $(HAVE_EXPLICIT_BZERO))';\
	  if [ x"$$V" != 'x0' -a x"$$V" != 'x1' ]; then\
	    echo -n 'Checking for explicit_bzero... ' >&2;\
	    echo '#include <string.h>\nint main(void){int i;explicit_bzero(&i,sizeof(i));return i;}'\
	    | $(CC) -xc -O0 -o/dev/null - 2>/dev/null; R=$$?;\
	    if [ x"$$R" = 'x0' ]; then\
	      echo 'yes' >&2;\
	      V='1';\
	    else\
	      echo 'no' >&2;\
	      V='0';\
	    fi;\
	  fi;\
	  echo -n "$$V"))
