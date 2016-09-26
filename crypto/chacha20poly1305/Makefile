#
# crypto/chacha20poly1305/Makefile
#

DIR=	chacha20poly1305
TOP=	../..
CC=	cc
CPP=	$(CC) -E
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CHAPOLY_ENC=

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST=chapolytest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=chacha20.c poly1305.c
LIBOBJ=chacha20.o poly1305.o $(CHAPOLY_ENC)

SRC= $(LIBSRC)

EXHEADER=chacha20poly1305.h
HEADER= $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

poly1305_x64.s:asm/poly1305_x64.pl
	$(PERL) asm/poly1305_x64.pl $(PERLASM_SCHEME) > $@
chacha20_avx.s:asm/chacha20_avx.pl
	$(PERL) asm/chacha20_avx.pl $(PERLASM_SCHEME) > $@
poly1305_avx.s:asm/poly1305_avx.pl
	$(PERL) asm/poly1305_avx.pl $(PERLASM_SCHEME) > $@
chacha20_avx2.s:asm/chacha20_avx2.pl
	$(PERL) asm/chacha20_avx2.pl $(PERLASM_SCHEME) > $@
poly1305_avx2.s:asm/poly1305_avx2.pl
	$(PERL) asm/poly1305_avx2.pl $(PERLASM_SCHEME) > $@

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

chapolytest: top chapolytest.c $(LIB)
	$(CC) $(CFLAGS) -Wall -Werror -g -o chapolytest cahpolytest.c $(LIB)

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.s *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

chacha20.o: ../../include/openssl/chacha20poly1305.h chacha20.c
poly1305.o: ../../include/openssl/chacha20poly1305.h poly1305.c
