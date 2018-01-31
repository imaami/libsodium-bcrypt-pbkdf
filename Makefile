AR := ar
CC := gcc
OBJCOPY := objcopy
CFLAGS := -std=gnu11 -march=native -O3 -fomit-frame-pointer -pipe -Wall -Wextra

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
		NO_REDEFINE_SYM="$(NO_REDEFINE_SYM)" \
		HAVE_EXPLICIT_BZERO="$(HAVE_EXPLICIT_BZERO)"

.PHONY: test
test: lib
	+$(MAKE) -C test CC="$(CC)" CFLAGS="$(CFLAGS)"

clean: clean-lib clean-test

.PHONY: clean-lib
clean-lib:
	+$(MAKE) -C src clean

.PHONY: clean-test
clean-test:
	+$(MAKE) -C test clean
