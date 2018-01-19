# libsodium-bcrypt-pbkdf

## Description

A static C library providing a single function, `sodium_bcrypt_pbkdf()`,
which is otherwise identical to openssh-portable's `bcrypt_pbkdf()` but
uses libsodium's SHA-512 function.

## Compiling

Change the `CFLAGS` variable in `Makefile` to suit your needs, then do

```make```

to build the static library (`src/libsodium-bcrypt-pbkdf.a`) and small
test program (`test/sodium-bcrypt-pbkdf-test`).

There is no install target, just copy the file.

## Usage

You'll need the library file `src/libsodium-bcrypt-pbkdf.a` and header
file `include/sodium_bcrypt_pbkdf.h`. You need to link against libsodium
when using the library in your project.

**NOTICE**: Although `sodium_bcrypt_pbkdf()` calls libsodium functions it
will *not* initialize libsodium automatically. You must call `sodium_init()`
yourself before calling `sodium_bcrypt_pbkdf()` (once is enough, of course).

## Does it work?

Excellent question. I have no idea. It should.
