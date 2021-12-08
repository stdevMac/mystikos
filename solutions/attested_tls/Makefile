.PHONY: all app cpio oe_enclave

TOP=$(abspath ../..)
include $(TOP)/defs.mak

OEENCLAVE = oe_enclave/enc/tlssrv_enc.signed
OEDUMP = $(BUILDDIR)/openenclave/bin/oesign dump -e $(OEENCLAVE)
PATH := $(PATH):$(BUILDDIR)/openenclave/bin
export PKG_CONFIG_PATH := $(BUILDDIR)/openenclave/share/pkgconfig
export AZDCAP_DEBUG_LOG_LEVEL := 0

all: myst cpio

#OPTS = --strace

run:
	# Kill the running instance of the TLS server before exit.
	@trap "exit" INT TERM
	@trap "killall -9 tlssrv_host" EXIT
	# Launch the TLS server the OE enclave
	@oe_enclave/host/tlssrv_host oe_enclave/enc/tlssrv_enc.signed hw &
	@echo "OE Enclave app started..."
	# Launch the TLS client with myst
	$(MYST_EXEC) rootfs /app/client 127.0.0.1 $(OPTS)
	@wait

myst:
	$(MAKE) -C $(TOP)/tools/myst

app:	app/peer_tee_identity.h
	cp $(TOP)/include/myst/tee.h app
	$(TOP)/scripts/appbuilder -v Dockerfile

oe_enclave:
	make -C oe_enclave/enc
	make -C oe_enclave/host

app/peer_tee_identity.h: oe_enclave
	# Generate peer identity file for the other enclave
	printf "#ifndef _PEER_TEE_IDENTITY_H\n" > app/peer_tee_identity.h
	printf "#define _PEER_TEE_IDENTITY_H\n\n" >> app/peer_tee_identity.h
	printf "#define PEER_PRODUCT_ID $(shell $(OEDUMP) | grep product_id= | cut -d= -f2)\n" >> app/peer_tee_identity.h
	printf "#define PEER_SVN $(shell $(OEDUMP) | grep security_version= | cut -d= -f2)\n" >> app/peer_tee_identity.h
	printf "#define PEER_DEBUG $(shell $(OEDUMP) | grep debug= | cut -d= -f2)\n" >> app/peer_tee_identity.h
	printf "#define PEER_MRENCLAVE \"$(shell $(OEDUMP) | grep mrenclave= | cut -d= -f2)\"\n" >> app/peer_tee_identity.h
	printf "#define PEER_MRSIGNER \"$(shell $(OEDUMP) | grep mrsigner= | cut -d= -f2)\"\n" >> app/peer_tee_identity.h
	printf "\n#endif" >> app/peer_tee_identity.h

cpio: app
	$(MYST) mkcpio appdir rootfs

clean:
	rm -rf rootfs appdir
	make clean -C oe_enclave/enc
	make clean -C oe_enclave/host
	rm -rf app/client app/tee.h app/peer_tee_identity.h
