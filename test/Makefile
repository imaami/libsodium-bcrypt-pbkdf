BIN := sodium-bcrypt-pbkdf-test
OBJ := sodium_bcrypt_pbkdf_test.o

INC = -I../include $(shell pkg-config --cflags libsodium)
LIB = ../src/libsodium-bcrypt-pbkdf.a $(shell pkg-config --libs libsodium)

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) -o $@ $(CFLAGS) -s $^ $(LIB)

.PHONY: clean
clean:
	rm -f $(BIN) $(OBJ)

%.o: %.c
	$(CC) -o $@ -c $(CFLAGS) $(INC) $<
