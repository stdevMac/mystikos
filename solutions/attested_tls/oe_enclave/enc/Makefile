CC = gcc
CXX = g++
C_COMPILER=$(CC)
CXX_COMPILER=$(CXX)

CFLAGS=$(shell pkg-config oeenclave-gcc --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-g++ --cflags)
LDFLAGS=$(shell pkg-config oeenclave-g++ --libs)
LDFLAGS+=$(shell pkg-config oeenclave-g++ --variable=mbedtlslibs)
INCDIR=$(shell pkg-config oeenclave-gcc --variable=includedir)
.PHONY: all build clean run

all:
	$(MAKE) build
	$(MAKE) sign

build:
	oeedger8r ../tlssrv.edl --trusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) -I/home/nethermind/connection/openenclave-curl/library/curl/include tlssrv.cpp 
	$(CXX) -c $(CFLAGS) $(CINCLUDES) gencreds.cpp
	$(CC) -c $(CFLAGS) $(CINCLUDES) -pthread tlssrv_t.c
	$(CXX) -o tlssrv_enc tlssrv.o gencreds.o tlssrv_t.o -L/home/nethermind/connection/openenclave-curl/build/openenclave-curl-prefix/src/openenclave-curl-build/curl/lib -lcurl $(LDFLAGS) -loehostsock -loehostresolver -loecore -loelibc -loesyscall

private.pem:
	openssl genrsa -out private.pem -3 3072

sign: private.pem
	oesign sign -e tlssrv_enc -c enc.conf -k private.pem

clean:
	rm -f *.o tlssrv_enc tlssrv_enc.signed tlssrv_t.* tlssrv_args.h private.pem
