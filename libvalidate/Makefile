SRCDIR=src
BINDIR=../bin

build:
	gcc -shared -Wall -fPIC -I$(SRCDIR) -lssl -lcrypto -s $(SRCDIR)/libvalidate.c -o $(BINDIR)/libvalidate.so

debug:
	gcc -shared -Wall -fPIC -I$(SRCDIR) -g -DDEBUG -lssl -lcrypto $(SRCDIR)/libvalidate.c -o $(BINDIR)/libvalidate.so

clean:
	rm -f $(SRCDIR)/*.o $(BINDIR)/libvalidate.so

