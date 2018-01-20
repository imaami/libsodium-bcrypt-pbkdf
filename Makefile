AR := ar
CC := gcc
CFLAGS := -std=gnu11 -march=native -O3 -fomit-frame-pointer -pipe -Wall -Wextra

# If you don't have explicit_bzero() you can run 'make HAVE_EXPLICIT_BZERO=0'
# instead of commenting out this line.
HAVE_EXPLICIT_BZERO := 1

all: lib test

.PHONY: lib
lib:
	+$(MAKE) -C src AR="$(AR)" CC="$(CC)" CFLAGS="$(CFLAGS)" HAVE_EXPLICIT_BZERO="$(HAVE_EXPLICIT_BZERO)"

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
