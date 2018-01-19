AR := ar
CC := gcc
CFLAGS := -std=gnu11 -march=native -O3 -fomit-frame-pointer -pipe -Wall -Wextra

all: lib test

.PHONY: lib
lib:
	+$(MAKE) -C src AR="$(AR)" CC="$(CC)" CFLAGS="$(CFLAGS)"

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
