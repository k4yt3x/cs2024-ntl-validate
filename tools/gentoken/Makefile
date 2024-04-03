CC=gcc
CFLAGS=-Wall -fPIC -Isrc
LDFLAGS=-no-pie -lssl -lcrypto
LIBNAME=gentoken
SRCDIR=src
BINDIR=../../bin

# Object file for the library
OBJ=$(SRCDIR)/gentoken.o

# Standard build
build: LDFLAGS += -s
build: $(BINDIR)/$(LIBNAME)

# Debug build
debug: CFLAGS += -g
debug: $(BINDIR)/$(LIBNAME)

$(BINDIR)/$(LIBNAME): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^

$(SRCDIR)/gentoken.o: $(SRCDIR)/gentoken.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(SRCDIR)/*.o $(BINDIR)/$(LIBNAME)

