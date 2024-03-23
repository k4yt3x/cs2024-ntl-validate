.PHONY: static dynamic debug clean test

SRCDIR=src
BINDIR=bin

# default values for the flags
COPY_PHONY_SYMBOLS=0
UPX_COMPRESS=0

dynamic:
	mkdir -p $(BINDIR)
	gcc -Wall -fPIC -I$(SRCDIR) -no-pie -lssl -lcrypto -s $(SRCDIR)/validate.c -o $(BINDIR)/validate
	python scripts/erase_gcc_info.py
ifeq ($(COPY_PHONY_SYMBOLS),1)
	bash scripts/copy_phony_symbols.sh
endif
ifeq ($(UPX_COMPRESS),1)
	upx bin/validate
endif

static:
	mkdir -p $(BINDIR)
	gcc -Wall -fPIC -I$(SRCDIR) -no-pie -static -s $(SRCDIR)/validate.c -o $(BINDIR)/validate -L/home/k4yt3x/projects/cybersci/openssl -lssl -lcrypto
	python scripts/erase_gcc_info.py
ifeq ($(COPY_PHONY_SYMBOLS),1)
	bash scripts/copy_phony_symbols.sh
endif
ifeq ($(UPX_COMPRESS),1)
	upx bin/validate
endif

debug:
	mkdir -p $(BINDIR)
	gcc -Wall -fPIC -I$(SRCDIR) -g -DDEBUG -no-pie -lssl -lcrypto $(SRCDIR)/validate.c -o $(BINDIR)/validate

clean:
	rm -f $(SRCDIR)/*.o $(BINDIR)/validate

test: static
	@$(BINDIR)/validate SzRZVDNY.4V43VnMchGsi2mF7Opq1zadt3JYvxox+T2M6NJuofuIDwTeX7vvAQqlaXrw67NPv; \
	ret=$$?; \
	if [ $$ret -ne 0 ]; then \
		echo "Test failed with exit code $$ret"; \
		exit $$ret; \
	else \
		echo 'Test succeeded'; \
	fi

