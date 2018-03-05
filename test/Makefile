CC := gcc
CFLAGS := -std=gnu11 -Og -ggdb -pipe -Wall -Wextra

LIBSODIUM_CFLAGS = $(shell pkg-config --cflags libsodium)
LIBSODIUM_LIBS = $(shell pkg-config --libs libsodium)

LIBCRYPTO_CFLAGS = $(shell pkg-config --cflags libcrypto)
LIBCRYPTO_LIBS = $(shell pkg-config --libs libcrypto)

override BIN := sodium-bcrypt-pbkdf-test
override OBJ := sodium_bcrypt_pbkdf_test.o sshkey.o hexdump.o

override LIB = ../src/libsodium-bcrypt-pbkdf.a $(LIBSODIUM_LIBS) $(LIBCRYPTO_LIBS)

override SSHKEY_CFLAGS = -I../include -I../src $(LIBSODIUM_CFLAGS) $(LIBCRYPTO_CFLAGS)

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) -o $@ $(CFLAGS) $^ $(LIB)

.PHONY: clean
clean:
	rm -f $(BIN) $(OBJ)

sodium_bcrypt_pbkdf_test.o: sodium_bcrypt_pbkdf_test.c
	$(CC) -o $@ -fPIC -c $(CFLAGS) $(LIBSODIUM_CFLAGS) $<

sshkey.o: sshkey.c check-explicit-bzero
	$(CC) -o $@ -fPIC -c $(CFLAGS) $(SSHKEY_CFLAGS) $(EXPLICIT_BZERO_CFLAGS) $<

hexdump.o: hexdump.c
	$(CC) -o $@ -fPIC -c $(CFLAGS) $<

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
