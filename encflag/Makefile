CC=gcc
CFLAGS=-Wall -fPIC -Isrc
LDFLAGS=-no-pie -lssl -lcrypto
LIBNAME=xtea_encrypt
SRCDIR=src
BINDIR=../bin

# Object file for the library
OBJ=$(SRCDIR)/xtea_encrypt.o

# Standard build
build: LDFLAGS += -s
build: $(BINDIR)/$(LIBNAME)

# Debug build
debug: CFLAGS += -g
debug: $(BINDIR)/$(LIBNAME)

$(BINDIR)/$(LIBNAME): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^

$(SRCDIR)/xtea_encrypt.o: $(SRCDIR)/xtea_encrypt.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(SRCDIR)/*.o $(BINDIR)/$(LIBNAME)

