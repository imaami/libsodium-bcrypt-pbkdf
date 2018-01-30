BIN := sodium-bcrypt-pbkdf-test
OBJ := sodium_bcrypt_pbkdf_test.o hexdump.o

DEP := libsodium libcrypto

INC = -I../include $(shell pkg-config --cflags $(DEP))
LIB = ../src/libsodium-bcrypt-pbkdf.a $(shell pkg-config --libs $(DEP))

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) -o $@ $(CFLAGS) -s $^ $(LIB)

.PHONY: clean
clean:
	rm -f $(BIN) $(OBJ)

sodium_bcrypt_pbkdf_test.o: sodium_bcrypt_pbkdf_test.c
	$(CC) -o $@ -c $(CFLAGS) $(INC) $<

hexdump.o: hexdump.c
	$(CC) -o $@ -c $(CFLAGS) $<
