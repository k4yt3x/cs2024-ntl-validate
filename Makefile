.PHONY: build debug clean test

SRCDIR=src
BINDIR=bin

build:
	mkdir -p $(BINDIR)
	gcc -Wall -fPIC -I$(SRCDIR) -no-pie -lssl -lcrypto -s $(SRCDIR)/validate.c -o $(BINDIR)/validate

debug:
	mkdir -p $(BINDIR)
	gcc -Wall -fPIC -I$(SRCDIR) -g -DDEBUG -no-pie -lssl -lcrypto $(SRCDIR)/validate.c -o $(BINDIR)/validate

clean:
	rm -f $(SRCDIR)/*.o $(BINDIR)/validate

test: build
	@$(BINDIR)/validate SzRZVDNY.4V43VnMchGsi2mF7Opq1zadt3JYvxox+T2M6NJuofuIDwTeX7vvAQqlaXrw67NPv; \
	ret=$$?; \
	if [ $$ret -ne 0 ]; then \
		echo "Test failed with exit code $$ret"; \
		exit $$ret; \
	else \
		echo 'Test succeeded'; \
	fi

