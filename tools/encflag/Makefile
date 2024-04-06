CC=gcc
CFLAGS=-Wall -fPIC -Isrc
LDFLAGS=-no-pie -lssl -lcrypto
LIBNAME=encflag
SRCDIR=src
BINDIR=../../bin

# Object file for the library
OBJ=$(SRCDIR)/encflag.o

# Standard build
build: LDFLAGS += -s
build: $(BINDIR)/$(LIBNAME)

# Debug build
debug: CFLAGS += -g
debug: $(BINDIR)/$(LIBNAME)

$(BINDIR)/$(LIBNAME): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^

$(SRCDIR)/encflag.o: $(SRCDIR)/encflag.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(SRCDIR)/*.o $(BINDIR)/$(LIBNAME)

